#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run, requireTool, writeLines, resolveOutputPath } from './lib/runner.js';
import { parseNmapXml } from './lib/nmap-parse.js';
import { openDb } from './lib/db.js';

// Data-store ports that fall OUTSIDE nmap's top-1000 (all rank by open-frequency,
// and the NoSQL/cache/graph stores sit well under the top-1000 cutoff of
// ~0.000152). --top-ports would silently skip these, so we union them in
// explicitly. RDBMS ports (3306/5432/1433/1521/50000) are already in the top-1000
// but listed here too so an explicit -p spec never loses them.
const DB_PORTS = [
  1433, 1521, 1526, 3050, 3306, 5432, 5433, 5984, 6379, 7000, 7001,
  7199, 7474, 7687, 8086, 8123, 9000, 9042, 9160, 9200, 9300, 11211,
  27017, 27018, 27019, 50000,
];

// nmap-services locations across common installs. Each line is
// `name\tport/proto\tfrequency\t# comment`; --top-ports N == the N highest
// frequencies. We read it so we can express "top-N UNION db-ports" as a single
// -p list — nmap will NOT union --top-ports with -p (it intersects, dropping the
// freq-0 NoSQL ports), so the only reliable single-pass form is an explicit -p.
const SERVICES_PATHS = [
  '/usr/share/nmap/nmap-services',
  '/usr/local/share/nmap/nmap-services',
  '/opt/homebrew/share/nmap/nmap-services',
];

function topTcpPorts(n: number): number[] | null {
  const file = SERVICES_PATHS.find((p) => fs.existsSync(p));
  if (!file) return null;
  const rows: Array<{ port: number; freq: number }> = [];
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    if (!line || line.startsWith('#')) continue;
    const [, portProto, freqStr] = line.split('\t');
    if (!portProto || !portProto.endsWith('/tcp')) continue;
    const port = parseInt(portProto, 10);
    const freq = parseFloat(freqStr ?? '0');
    if (Number.isFinite(port) && Number.isFinite(freq)) rows.push({ port, freq });
  }
  rows.sort((a, b) => b.freq - a.freq);
  return rows.slice(0, n).map((r) => r.port);
}

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  // Own flags (before --): --nse <categories>
  let nseCategories: string | null = null;
  let topPorts = 1000;
  // Per-host cap. Was 180s but connect-scan of top-1000 ports against
  // heavily filtered targets (Hungarian gov perimeters, cloud WAFs) blows
  // past that before enumerating anything, and every timed-out host emits
  // ZERO port rows to the DB. 600s is enough headroom for filtered hosts
  // at --min-rate 500 while still bounding truly-dead hosts.
  let hostTimeout = '600s';
  let dbPorts: number[] = DB_PORTS; // union'd in by default so DB stores aren't missed
  let vulners = false;             // --vulners: append `--script vulners` for CVE tagging
  const passthrough: string[] = [];
  for (let i = 0; i < opts.extraArgs.length; i++) {
    const a = opts.extraArgs[i]!;
    const nxt = () => opts.extraArgs[++i]!;
    if (a === '--nse') nseCategories = nxt();
    else if (a === '--top-ports') topPorts = parseInt(nxt(), 10);
    else if (a === '--host-timeout') hostTimeout = nxt();
    else if (a === '--db-ports') dbPorts = nxt().split(',').map((p) => parseInt(p.trim(), 10)).filter(Number.isFinite);
    else if (a === '--no-db-ports') dbPorts = [];
    else if (a === '--vulners') vulners = true;
    else passthrough.push(a);
  }

  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('nmap', `
Runs: nmap -Pn -sV -T4 --host-timeout 180s --max-retries 2 -p <top-1000 ∪ db-ports> <targets> -oX out.xml
Emits: parsed JSONL + raw XML into the run dir (or --out / cwd).

Wrapper flags (before '--'):
  --nse <categories>   NSE scripts, comma-sep. e.g. 'vuln,safe,discovery,http'
                       Adds \`--script <categories>\` to the nmap invocation.
  --vulners            Append \`--script vulners\` — queries vulners.com CVE DB
                       against nmap's fingerprinted product+version and emits
                       one finding per matched CVE, severity from CVSS.
  --top-ports <N>      Breadth of the frequency-ranked port set (default: 1000).
                       Materialised from nmap-services and union'd with db ports.
  --db-ports <list>    Override the DB port list (comma-sep) union'd into -p.
                       Default: ${DB_PORTS.join(',')}
  --no-db-ports        Disable the DB-port union; use plain --top-ports <N>.
  --host-timeout <t>   Per-host cap so dead/filtered hosts can't hang the batch
                       (default: 180s). e.g. 120s, 5m`));
    process.exit(opts.targetsFile ? 0 : 1);
  }
  await requireTool('nmap');
  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  // Open DB first so we have a runId to scope output paths.
  const now = new Date().toISOString();
  const db = opts.sqlite ? openDb(opts.sqlite) : null;
  const runId = db ? db.startRun('nmap', { targets: targets.length, extraArgs: opts.extraArgs }, now) : null;

  const outFile = resolveOutputPath(opts, runId, 'nmap.jsonl');
  const xmlOut = resolveOutputPath({ ...opts, outFile: null }, runId, 'nmap.xml');
  const tmpTargets = resolveOutputPath({ ...opts, outFile: null }, runId, 'nmap-targets.txt');
  writeLines(tmpTargets, targets);
  // Merge --nse and --vulners into a single --script arg (nmap allows a
  // comma-separated list). Duplicates are harmless — nmap dedupes internally.
  const nseParts: string[] = [];
  if (nseCategories) nseParts.push(nseCategories);
  if (vulners) nseParts.push('vulners');
  const nseArgs = nseParts.length ? ['--script', nseParts.join(',')] : [];
  // Port selection: prefer an explicit -p list that unions the top-N ports with
  // the DB ports, so freq-0 NoSQL stores (Redis/Mongo/Cassandra/...) are actually
  // scanned. nmap intersects --top-ports with -p rather than unioning, so we
  // can't just append -p; we materialise the top-N list ourselves. If the
  // nmap-services file is unreadable, fall back to --top-ports (+ a warning) so
  // the tool still runs, and still append DB ports as a best-effort -p.
  const top = dbPorts.length ? topTcpPorts(topPorts) : null;
  let portArgs: string[];
  if (dbPorts.length && top) {
    const merged = Array.from(new Set([...top, ...dbPorts])).sort((a, b) => a - b);
    portArgs = ['-p', merged.join(',')];
    console.error(`ports: top-${topPorts} (${top.length}) + ${dbPorts.length} db ports = ${merged.length} unique`);
  } else if (dbPorts.length) {
    console.error(`WARN: nmap-services not found; cannot union top-${topPorts} with db ports — using --top-ports ${topPorts} then -p db-ports (nmap will intersect; run a second -p pass to be sure)`);
    portArgs = ['--top-ports', String(topPorts)];
  } else {
    portArgs = ['--top-ports', String(topPorts)];
  }
  // --host-timeout bounds each host (dead/filtered hosts otherwise make -sV hang
  // for many minutes and block the whole batch). -T4 + --max-retries 2 keep it
  // brisk for internet targets. All overridable via passthrough (last wins).
  // --min-rate 500 forces nmap to keep the probe rate up when many ports
  // are dropping silently. Without it, the default congestion-avoidance
  // logic slows to a crawl on filter-heavy targets and the host-timeout
  // fires before real ports get probed.
  const args = ['-Pn', '-sV', '-T4', '--host-timeout', hostTimeout, '--max-retries', '2', '--min-rate', '500', ...portArgs, '-iL', tmpTargets, '-oX', xmlOut, ...nseArgs, ...passthrough];
  console.error(`nmap ${args.join(' ')}`);
  const r = await run('nmap', args);
  if (r.code !== 0) console.error(`nmap exited ${r.code}: ${r.stderr.slice(0, 300)}`);
  const xml = fs.readFileSync(xmlOut, 'utf8');
  const hosts = parseNmapXml(xml);
  const jsonl = hosts.map((h) => JSON.stringify(h)).join('\n') + '\n';
  fs.writeFileSync(outFile, jsonl);
  const totalPorts = hosts.reduce((a, h) => a + h.ports.length, 0);
  console.error(`${hosts.length} up hosts, ${totalPorts} open ports`);
  console.error(`  raw xml: ${xmlOut}`);
  console.error(`  jsonl:   ${outFile}`);

  if (db && runId !== null) {
    let cveFindings = 0;
    for (const h of hosts) {
      const target = h.hostnames[0] ?? h.ip;
      for (const p of h.ports) {
        db.insertPort({
          target, ip: h.ip,
          port: p.port, protocol: p.protocol,
          service: p.service ?? null, product: p.product ?? null,
          version: p.version ?? null, tunnel: p.tunnel ?? null,
          extrainfo: p.extrainfo ?? null,
        }, now, runId);
        // Emit one finding per CVE the vulners script matched. Severity via CVSS
        // v2 buckets: 9.0+ critical, 7.0+ high, 4.0+ medium, else low.
        for (const s of p.scripts ?? []) {
          for (const c of s.cves ?? []) {
            const cvss = c.cvss ?? 0;
            const severity =
              cvss >= 9 ? 'critical' :
              cvss >= 7 ? 'high' :
              cvss >= 4 ? 'medium' : 'low';
            const productLabel = [p.product, p.version].filter(Boolean).join(' ') || `${p.service ?? p.port}`;
            db.insertFinding({
              tool: 'nmap-vulners',
              target,
              category: 'cve',
              severity,
              title: `${c.id} on ${productLabel} (${target}:${p.port})${c.is_exploit ? ' [EXPLOIT AVAILABLE]' : ''}`,
              cve: c.id,
              matched_at: `${target}:${p.port}`,
              meta: { cvss, is_exploit: c.is_exploit, product: p.product, version: p.version, service: p.service, port: p.port },
            }, now, runId);
            cveFindings++;
          }
        }
      }
    }
    db.finishRun(runId, { targetsCount: targets.length, findingsCount: totalPorts + cveFindings, at: new Date().toISOString() });
    db.close();
    console.error(`  sqlite: ${path.resolve(opts.sqlite!)} (+${totalPorts} ports${cveFindings ? `, +${cveFindings} CVE findings` : ''}, run #${runId})`);
  }
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
