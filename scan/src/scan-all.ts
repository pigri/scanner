#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { parseCommonCli, commonUsage, prepareTargets, run } from './lib/runner.js';

async function step(name: string, cmd: string, args: string[]): Promise<number> {
  const start = Date.now();
  console.error(`\n>>> START ${name}`);
  const r = await run(cmd, args);
  const dt = ((Date.now() - start) / 1000).toFixed(1);
  console.error(`<<< DONE  ${name} in ${dt}s (exit ${r.code})`);
  if (r.stderr) {
    // prefix each line with tool name so parallel output stays legible
    for (const line of r.stderr.split('\n')) if (line) process.stderr.write(`[${name}] ${line}\n`);
  }
  return r.code;
}

async function main(): Promise<void> {
  const opts = parseCommonCli(process.argv);
  if (opts.help || !opts.targetsFile) {
    console.error(commonUsage('scan-all', `
Runs the full scan pipeline on --targets. Default: parallel.

Dependency graph:
  Stage 1 (fast):       httpx     — its output feeds wpscan + katana live filter
  Stage 2 (parallel):   nmap (--vulners: NSE CVE tagging via vulners.nse),
                        nuclei, takeover, testssl, gowitness,
                        rustscan (full 1-65535, TCP-connect),
                        naabu    (full 1-65535, TCP-connect — WG/tun-safe),
                        masscan  (full 1-65535, raw SYN — auto-skips over
                                  wg*/tun* interfaces),
                        katana   (crawl live hosts → discovered_urls table),
                        gau      (historical URLs from wayback/OTX → discovered_urls),
                        waybackurls (CDX-index URLs → discovered_urls),
                        dnsx     (A/AAAA/CNAME/MX/TXT/NS/SOA → dns_records),
                        checkdmarc (SPF/DMARC/MTA-STS/DNSSEC → findings)  ← concurrent
  Stage 3 (parallel):   wpscan (WordPress-flagged hosts from httpx),
                        nuclei-urls (rescan katana URLs — needs Stage-2 katana done),
                        kiterunner (API-route brute; api-shaped hosts only),
                        secrets (fetch JS/JSON from discovered_urls + gitleaks),
                        headers (modern security-header audit per live URL),
                        ffuf (curated path list — status/length dedup),
                        content-sigs (WAF-immune body-signature probes — .git/.env/etc.),
                        sslyze (modern TLS audit: Heartbleed/ROBOT/CCS/SSLv3/TLS1.x),
                        cve-rollup (aggregate findings.cve → cves table),
                        cname-takeover (dangling-CNAME check vs 29 providers),
                        data-integrity (self-heal report_queue + cve rollup drift),
                        enum4linux-ng + smbmap + rpcclient (--live-only, gated on
                        nmap-detected port 445/139)

Each stage inherits --scope / --strict / --targets / --sqlite.

Env vars:
  SKIP=wpscan,testssl,smb   skip these stages ("smb" skips all three SMB tools)
  SEQUENTIAL=1              fall back to strict sequential (legacy behaviour)
  SCAN_DEEP=1               widen the profile — katana -depth 3, kiterunner
                            --all-hosts, ffuf/nuclei longer timeouts. Set by
                            deep-audit.ts for the zero-finding rescan pass.`));
    process.exit(opts.targetsFile ? 0 : 1);
  }

  const { targets } = prepareTargets(opts);
  if (!targets.length) { console.error('no in-scope targets'); process.exit(1); }

  const skip = new Set((process.env['SKIP'] ?? '').split(',').map((s) => s.trim()).filter(Boolean));
  const runOne = (name: string): boolean => !skip.has(name);
  const sequential = process.env['SEQUENTIAL'] === '1' || process.env['SEQUENTIAL']?.toLowerCase() === 'true';
  // SCAN_DEEP=1 widens the profile for the "were-they-locked-down-or-under-scanned?"
  // audit: katana depth 3 (default 2), kiterunner drops the api-shape filter,
  // ffuf/nuclei get more time. Set by deep-audit.ts + surfaced here so the same
  // scan-all binary handles both normal and deep passes.
  const deep = process.env['SCAN_DEEP'] === '1';
  if (deep) console.error('SCAN_DEEP=1 — widening katana/kiterunner/ffuf/nuclei profiles');

  const targetsArg = ['--targets', opts.targetsFile];
  const scopeArg = opts.scopeFile ? ['--scope', opts.scopeFile] : [];
  const strictArg = opts.strict ? ['--strict'] : [];
  const sqliteArg = opts.sqlite ? ['--sqlite', opts.sqlite] : [];
  const common = [...targetsArg, ...scopeArg, ...strictArg, ...sqliteArg];

  const tsx = 'npx';
  // Per-tool extra flags — set via env vars, e.g. TESTSSL_FLAGS="--live-only --concurrency 6"
  const perToolExtra = (tool: string): string[] => {
    const env = process.env[`${tool.toUpperCase()}_FLAGS`];
    return env ? env.split(/\s+/).filter(Boolean) : [];
  };
  // Deep-mode per-tool overrides. Applied UNDER the env NUCLEI_FLAGS/etc. so
  // an operator override still wins (the merged list ends up as `-- deep,
  // per` and each wrapper's own arg loop takes the last-parsed value).
  const deepDefaults: Record<string, string[]> = deep ? {
    katana:    ['--depth', '3', '--crawl-timeout', '120'],
    kiterunner:['--all-hosts', '--host-timeout', '600'],
    nuclei:    ['--scan-timeout', '1800'],
    ffuf:      ['--host-timeout', '180'],
  } : {};
  const cmd = (script: string, extra: string[] = []) => {
    const per = perToolExtra(script);
    const deepArgs = deepDefaults[script] ?? [];
    // Per-tool extras go after `--` so parseCommonCli routes them to extraArgs
    // (where the wrapper's own arg loop can pick up --live-only, --concurrency, etc.)
    const tail = (per.length || deepArgs.length) ? ['--', ...deepArgs, ...per] : [];
    return ['tsx', `src/${script}.ts`, ...common, ...extra, ...tail];
  };

  const pipelineStart = Date.now();

  // Stage 1: httpx (blocking — wpscan needs its output)
  if (runOne('httpx')) await step('httpx', tsx, cmd('httpx'));

  // Stage 2: independent tools in parallel. rustscan/masscan are additive
  // port-discovery — they widen coverage past nmap's top-1000+DB_PORTS union
  // (rustscan does full 1-65535 TCP-connect, masscan does full raw-SYN sweep).
  // masscan self-skips over point-to-point tunnels (wg*/tun*), so leaving it
  // in the default set is safe inside scanvpn.
  const stage2: Array<[string, string[]]> = [];
  if (runOne('nmap')) {
    // Always run vulners.nse — CVE-tagging any versioned service is free extra
    // signal. Ops can still override via NMAP_FLAGS in the environment.
    const per = perToolExtra('nmap');
    stage2.push(['nmap', ['tsx', 'src/nmap.ts', ...common, '--', '--vulners', ...per]]);
  }
  if (runOne('rustscan'))  stage2.push(['rustscan',  cmd('rustscan')]);
  if (runOne('naabu'))     stage2.push(['naabu',     cmd('naabu')]);
  if (runOne('nmap-udp'))  stage2.push(['nmap-udp',  cmd('nmap-udp')]);
  if (runOne('masscan'))   stage2.push(['masscan',   cmd('masscan')]);
  if (runOne('nuclei'))    stage2.push(['nuclei',    cmd('nuclei')]);
  if (runOne('takeover'))  stage2.push(['takeover',  cmd('takeover')]);
  if (runOne('testssl'))   stage2.push(['testssl',   cmd('testssl')]);
  if (runOne('gowitness')) stage2.push(['gowitness', cmd('gowitness')]);
  if (runOne('katana'))     stage2.push(['katana',      cmd('katana')]);
  if (runOne('gau'))        stage2.push(['gau',         cmd('gau')]);
  if (runOne('waybackurls'))stage2.push(['waybackurls', cmd('waybackurls')]);
  if (runOne('dnsx'))       stage2.push(['dnsx',        cmd('dnsx')]);
  if (runOne('checkdmarc')) stage2.push(['checkdmarc',  cmd('checkdmarc')]);

  console.error(`\n>>> STAGE 2 (${sequential ? 'sequential' : 'parallel'}): ${stage2.map((s) => s[0]).join(', ')}`);
  if (sequential) {
    for (const [name, args] of stage2) await step(name, tsx, args);
  } else {
    await Promise.all(stage2.map(([name, args]) => step(name, tsx, args)));
  }

  // Stage 3: wpscan (needs httpx from stage 1) + SMB tools (need nmap ports
  // from stage 2). They share no data with each other so run in parallel.
  const stage3: Array<[string, string[]]> = [];

  if (runOne('wpscan')) {
    const wpTargets = extractWpTargets();
    if (wpTargets.length) {
      const wpFile = path.resolve('wp-targets.txt');
      fs.writeFileSync(wpFile, wpTargets.join('\n') + '\n');
      const wpCommon = ['--targets', wpFile, ...scopeArg, ...strictArg, ...sqliteArg];
      stage3.push([`wpscan (${wpTargets.length} WP hosts)`, ['tsx', 'src/wpscan.ts', ...wpCommon]]);
    } else {
      console.error('\n=== wpscan === skipped (no WordPress hosts detected in httpx)');
    }
  }

  // URL-level nuclei rescan against katana's crawl output. Depends on Stage 2
  // katana finishing, so it lives in Stage 3. SKIP=nuclei-urls turns it off.
  if (runOne('nuclei-urls')) {
    const nucleiUrls: string[] = ['tsx', 'src/nuclei.ts', ...common, '--', '--from-urls', '--live-only'];
    stage3.push(['nuclei-urls', nucleiUrls]);
  }
  // kiterunner — API-route brute, api-shaped hosts only. Needs Stage-2 httpx
  // to have populated http_probes (live-only + api-shape filter both read it).
  if (runOne('kiterunner')) stage3.push(['kiterunner', cmd('kiterunner')]);
  // secrets — fetches JS/JSON from discovered_urls + gitleaks. Depends on
  // Stage-2 katana/gau/waybackurls having populated URLs.
  if (runOne('secrets'))    stage3.push(['secrets',    cmd('secrets')]);
  // headers — modern security-header audit. Depends on Stage-2 httpx.
  if (runOne('headers'))    stage3.push(['headers',    cmd('headers')]);
  // ffuf — curated high-signal path list (backup files, .env, .git,
  // phpinfo, server-status). Needs Stage-2 httpx (live filter).
  if (runOne('ffuf'))       stage3.push(['ffuf',       cmd('ffuf')]);
  // content-sigs — WAF-immune path exposure check. Body-signature matches
  // against .git / .env / phpinfo / actuator / etc. Complements ffuf: ffuf
  // finds distinct-length responses, content-sigs finds real artefact
  // contents. On heavily-WAFed estates ffuf drops to 0, content-sigs still
  // works.
  if (runOne('content-sigs')) stage3.push(['content-sigs', cmd('content-sigs')]);
  // sslyze — modern TLS audit that catches what testssl misses (ROBOT/CCS/
  // Heartbleed as typed findings, SCT count, chain order). Depends on
  // Stage-2 httpx or nmap (443 port detection).
  if (runOne('sslyze'))     stage3.push(['sslyze',     cmd('sslyze')]);
  // cve-rollup — aggregate every tool's findings.cve rows into the cves
  // table. Idempotent; must run AFTER everything that emits CVEs, so it's
  // stage 3 alongside the URL/secret/header stuff. SKIP=cve-rollup skips.
  if (runOne('cve-rollup')) stage3.push(['cve-rollup', ['tsx', 'src/cve-rollup.ts', '--sqlite', opts.sqlite ?? 'scan.db']]);
  // cname-takeover — cross-joins dns_records.CNAME against the takeover
  // provider list. Sweeps the whole DB (not just the batch) so newly-added
  // providers get retested against historical CNAMEs.
  if (runOne('cname-takeover')) {
    const cta: string[] = ['tsx', 'src/cname-takeover.ts', ...common, '--', '--all'];
    stage3.push(['cname-takeover', cta]);
  }
  // data-integrity — self-heal (report_queue orphans + cve rollup drift).
  // Runs last so it observes the batch's completed state.
  if (runOne('data-integrity')) stage3.push(['data-integrity', ['tsx', 'src/data-integrity.ts', '--sqlite', opts.sqlite ?? 'scan.db']]);

  // SMB layer — each wrapper uses --live-only to filter to hosts the ports table
  // has seen listening on 445/139. If nmap surfaced no SMB in the current batch's
  // hosts the wrappers exit cleanly at their own live-filter (no-op cost is one
  // sqlite query per tool). SKIP=smb skips all three; SKIP=smbmap etc. skips
  // individually.
  const smbSkip = skip.has('smb');
  const smbCmd = (script: string): string[] => [
    'tsx', `src/${script}.ts`,
    ...common,
    '--', '--live-only',
  ];
  if (!smbSkip && runOne('enum4linux-ng')) stage3.push(['enum4linux-ng', smbCmd('enum4linux-ng')]);
  if (!smbSkip && runOne('smbmap'))        stage3.push(['smbmap',        smbCmd('smbmap')]);
  if (!smbSkip && runOne('rpcclient'))     stage3.push(['rpcclient',     smbCmd('rpcclient')]);

  if (stage3.length) {
    console.error(`\n>>> STAGE 3 (${sequential ? 'sequential' : 'parallel'}): ${stage3.map((s) => s[0]).join(', ')}`);
    if (sequential) {
      for (const [name, args] of stage3) await step(name, tsx, args);
    } else {
      await Promise.all(stage3.map(([name, args]) => step(name, tsx, args)));
    }
  }

  const totalDt = ((Date.now() - pipelineStart) / 1000).toFixed(1);
  console.error(`\nscan-all pipeline finished in ${totalDt}s`);
}

// Find all httpx.jsonl outputs across run dirs (default runs/<id>/httpx.jsonl)
// so wpscan sees fresh data even when we're resuming an interrupted pipeline.
function extractWpTargets(): string[] {
  const seen = new Set<string>();
  const candidates: string[] = ['httpx.jsonl'];
  const runsDir = path.resolve('runs');
  if (fs.existsSync(runsDir)) {
    for (const id of fs.readdirSync(runsDir)) {
      const p = path.join(runsDir, id, 'httpx.jsonl');
      if (fs.existsSync(p)) candidates.push(p);
    }
  }
  for (const file of candidates) {
    if (!fs.existsSync(file)) continue;
    for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try {
        const row = JSON.parse(line) as { url?: string; tech?: string[]; technologies?: string[] };
        const tech = [...(row.tech ?? []), ...(row.technologies ?? [])].map((t) => t.toLowerCase());
        if (tech.some((t) => t.includes('wordpress'))) {
          const url = row.url ?? '';
          if (url) seen.add(url);
        }
      } catch { /* ignore */ }
    }
  }
  return [...seen];
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
