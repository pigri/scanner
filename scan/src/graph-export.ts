#!/usr/bin/env -S node --loader tsx
// graph-export: emit the estate as a Cytoscape-format JSON graph.
//
// Nodes: hosts, ports, tech, CVEs, DNS names (MX/NS/CNAME peers)
// Edges: host→port, host→tech (from httpx tech_json), host→cve (via cves
//        table), host→dns-peer (MX/NS/CNAME hostnames the host references)
//
// Optional --target <fqdn> restricts to a single-host subgraph (that host,
// everything it depends on, and everything that depends on it).
//
// Optional --html renders a self-contained HTML viewer using Cytoscape.js
// from CDN — one-page dashboard, no server.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import Database from 'better-sqlite3';

// Cached Cytoscape.js + cose-bilkent bundles for the --png path (headless
// chrome can't fetch from the network under --virtual-time-budget, so the
// scripts must be inlined). Cache lives in ~/.cache/gen0sec-graph so the
// first PNG render populates it once, subsequent renders reuse.
const JS_CACHE_DIR = path.join(os.homedir(), '.cache', 'gen0sec-graph');
// Only Cytoscape itself — we use the built-in `cose` layout for PNG rendering
// (cose-bilkent has a transitive dep chain that doesn't inline cleanly:
// bilkent → cose-base → layout-base). Built-in cose gives comparable output
// for our node counts and needs zero extensions.
const JS_SOURCES: Array<{ name: string; url: string }> = [
  { name: 'cytoscape.min.js', url: 'https://unpkg.com/cytoscape@3.30.2/dist/cytoscape.min.js' },
];
async function ensureCytoscapeInline(): Promise<string> {
  fs.mkdirSync(JS_CACHE_DIR, { recursive: true });
  let out = '';
  for (const s of JS_SOURCES) {
    const local = path.join(JS_CACHE_DIR, s.name);
    if (!fs.existsSync(local) || fs.statSync(local).size < 10_000) {
      console.error(`fetching ${s.url} → ${local}`);
      const resp = await fetch(s.url);
      if (!resp.ok) throw new Error(`fetch ${s.url}: HTTP ${resp.status}`);
      fs.writeFileSync(local, await resp.text());
    }
    out += `<script>\n${fs.readFileSync(local, 'utf8')}\n</script>\n`;
  }
  return out;
}

interface CyNode { data: { id: string; label: string; type: string; [k: string]: unknown } }
interface CyEdge { data: { id: string; source: string; target: string; kind: string; [k: string]: unknown } }

function usage(): void {
  console.error(`Usage: graph-export --sqlite <path> [--target <fqdn>] [--out <file>] [--html|--png]

Emits the estate as a Cytoscape-format JSON graph: hosts, ports, tech, CVEs,
DNS peers, shared certs.

Options:
  --sqlite <path>        default: scan.db
  --target <fqdn>        restrict to a single-host subgraph
  --out <file>           JSON to file (default: stdout); HTML: default graph.html; PNG: default graph.png
  --html                 self-contained interactive viewer (Cytoscape.js CDN)
  --png                  headless-Chrome render of --html mode to a static PNG
  --width <px>           PNG canvas width  (default: 2400)
  --height <px>          PNG canvas height (default: 1600)
  --settle-ms <ms>       time to give the layout engine before screenshotting (default: 6000)
  --min-severity <s>     only include CVEs at or above this severity (default: high)
`);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  let dbPath = 'scan.db';
  let target: string | null = null;
  let out: string | null = null;
  let html = false;
  let png = false;
  let width = 2400;
  let height = 1600;
  let settleMs = 6000;
  let minSeverity = 'high';
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '-h' || a === '--help') { usage(); process.exit(0); }
    if (a === '--sqlite' || a === '--db') dbPath = argv[++i]!;
    else if (a === '--target') target = argv[++i]!;
    else if (a === '--out') out = argv[++i]!;
    else if (a === '--html') html = true;
    else if (a === '--png') { png = true; html = true; }   // --png implies --html
    else if (a === '--width') width = parseInt(argv[++i]!, 10);
    else if (a === '--height') height = parseInt(argv[++i]!, 10);
    else if (a === '--settle-ms') settleMs = parseInt(argv[++i]!, 10);
    else if (a === '--min-severity') minSeverity = argv[++i]!;
  }

  const db = new Database(dbPath, { readonly: true });
  const sevRank: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const minRank = sevRank[minSeverity] ?? 3;

  const nodes = new Map<string, CyNode>();
  const edges: CyEdge[] = [];
  const addNode = (id: string, label: string, type: string, extra: Record<string, unknown> = {}): void => {
    if (!nodes.has(id)) nodes.set(id, { data: { id, label, type, ...extra } });
  };
  const addEdge = (source: string, target: string, kind: string, extra: Record<string, unknown> = {}): void => {
    edges.push({ data: { id: `${source}--${kind}--${target}`, source, target, kind, ...extra } });
  };

  const targetFilter = target ? "AND target = ?" : "";
  const targetParams = target ? [target] : [];

  // --- hosts ------------------------------------------------------------
  const hostRows = db.prepare(
    `SELECT DISTINCT target FROM (
       SELECT target FROM ports ${target ? 'WHERE target = ?' : ''}
       UNION SELECT target FROM http_probes ${target ? 'WHERE target = ?' : ''}
       UNION SELECT target FROM findings ${target ? 'WHERE target = ?' : ''}
     )`
  ).all(...(target ? [target, target, target] : [])) as { target: string }[];
  for (const h of hostRows) addNode(`h:${h.target}`, h.target, 'host');

  // --- ports (per host) -------------------------------------------------
  const portRows = db.prepare(
    `SELECT DISTINCT target, port, protocol, service, product, version
     FROM ports WHERE 1=1 ${targetFilter} ORDER BY target, port`
  ).all(...targetParams) as { target: string; port: number; protocol: string; service: string | null; product: string | null; version: string | null }[];
  for (const p of portRows) {
    const pid = `p:${p.target}:${p.port}/${p.protocol}`;
    const label = `${p.port}/${p.protocol}${p.service ? ` ${p.service}` : ''}`;
    addNode(pid, label, 'port', { port: p.port, product: p.product, version: p.version, service: p.service });
    addNode(`h:${p.target}`, p.target, 'host');
    addEdge(`h:${p.target}`, pid, 'listens_on');
  }

  // --- tech (from httpx tech_json) --------------------------------------
  const techRows = db.prepare(
    `SELECT DISTINCT target, tech_json FROM http_probes WHERE tech_json IS NOT NULL ${targetFilter}`
  ).all(...targetParams) as { target: string; tech_json: string }[];
  for (const r of techRows) {
    try {
      const tech = JSON.parse(r.tech_json) as string[];
      for (const t of tech) {
        const tid = `t:${t}`;
        addNode(tid, t, 'tech');
        addNode(`h:${r.target}`, r.target, 'host');
        addEdge(`h:${r.target}`, tid, 'runs');
      }
    } catch { /* ignore */ }
  }

  // --- CVEs above severity threshold ------------------------------------
  const cveRows = db.prepare(
    `SELECT target, cve_id, severity, cvss, exploit
     FROM cves WHERE cve_id GLOB 'CVE-*' ${targetFilter} ORDER BY cvss DESC`
  ).all(...targetParams) as { target: string; cve_id: string; severity: string | null; cvss: number | null; exploit: number }[];
  for (const c of cveRows) {
    if ((sevRank[c.severity ?? 'info'] ?? 0) < minRank) continue;
    const cid = `c:${c.cve_id}`;
    addNode(cid, c.cve_id, 'cve', { severity: c.severity, cvss: c.cvss, exploit: !!c.exploit });
    addNode(`h:${c.target}`, c.target, 'host');
    addEdge(`h:${c.target}`, cid, 'vulnerable_to', { severity: c.severity });
  }

  // --- DNS peers (MX/NS/CNAME hostnames) --------------------------------
  const dnsRows = db.prepare(
    `SELECT target, type, value FROM dns_records
     WHERE type IN ('MX','NS','CNAME') ${targetFilter}`
  ).all(...targetParams) as { target: string; type: string; value: string }[];
  for (const d of dnsRows) {
    const peer = d.value.replace(/\.$/, '');
    if (peer === d.target) continue;
    const pid = `d:${peer}`;
    addNode(pid, peer, 'dns-peer', { rtype: d.type });
    addNode(`h:${d.target}`, d.target, 'host');
    addEdge(`h:${d.target}`, pid, d.type.toLowerCase());
  }

  // --- Shared-cert peers (blast radius via certificates.fingerprint_sha256)
  // Emit one 'cert' node per shared fingerprint and connect every host that
  // presents it. In single-target mode, only include the target's own certs;
  // otherwise sweep certs shared across ≥ 2 hosts (the interesting case for
  // blast-radius analysis).
  const certSql = target
    ? `SELECT c1.target AS target, c1.fingerprint_sha256 fp, c1.common_name cn, c1.not_after
       FROM certificates c1
       WHERE c1.target = ? AND c1.fingerprint_sha256 IS NOT NULL`
    : `SELECT c.target AS target, c.fingerprint_sha256 fp, c.common_name cn, c.not_after
       FROM certificates c
       WHERE c.fingerprint_sha256 IN (
         SELECT fingerprint_sha256 FROM certificates
         WHERE fingerprint_sha256 IS NOT NULL
         GROUP BY fingerprint_sha256 HAVING COUNT(DISTINCT target) > 1
       )`;
  const certRows = db.prepare(certSql).all(...(target ? [target] : [])) as { target: string; fp: string; cn: string | null; not_after: string | null }[];
  // For single-target mode we need to expand peers too — fetch every host
  // presenting the same fingerprints so the graph shows the full group.
  const fingerprints = new Set(certRows.map((r) => r.fp));
  if (target && fingerprints.size) {
    const ph = [...fingerprints].map(() => '?').join(',');
    const peers = db.prepare(
      `SELECT target, fingerprint_sha256 fp, common_name cn, not_after
       FROM certificates WHERE fingerprint_sha256 IN (${ph})`
    ).all(...fingerprints) as { target: string; fp: string; cn: string | null; not_after: string | null }[];
    for (const p of peers) certRows.push(p);
  }
  const seenCert = new Set<string>();
  for (const r of certRows) {
    if (!r.fp) continue;
    const cid = `cert:${r.fp}`;
    if (!seenCert.has(cid)) {
      addNode(cid, r.cn ?? r.fp.slice(0, 12), 'cert', { fingerprint: r.fp, common_name: r.cn, not_after: r.not_after });
      seenCert.add(cid);
    }
    addNode(`h:${r.target}`, r.target, 'host');
    addEdge(`h:${r.target}`, cid, 'presents');
  }

  const graph = { elements: { nodes: [...nodes.values()], edges } };
  console.error(`graph: ${nodes.size} node(s), ${edges.length} edge(s)`);

  db.close();

  if (png) {
    // Write the HTML to a temp file so headless-chrome can load it via file://,
    // wait for cytoscape layout to settle, then screenshot to PNG. Cytoscape
    // JS is inlined (--virtual-time-budget can't accelerate network fetches).
    const outFile = out ?? 'graph.png';
    const inlineJs = await ensureCytoscapeInline();
    const tmp = path.join(os.tmpdir(), `graph-${Date.now()}.html`);
    fs.writeFileSync(tmp, renderHtml(graph, target, { forPng: true, inlineJs }));
    await renderPng(tmp, outFile, width, height, settleMs);
    fs.unlinkSync(tmp);
    console.error(`wrote ${outFile} (${width}×${height}px, settle=${settleMs}ms)`);
  } else if (html) {
    const outFile = out ?? 'graph.html';
    fs.writeFileSync(outFile, renderHtml(graph, target));
    console.error(`wrote ${outFile}`);
  } else {
    const outFile = out ?? '-';
    const json = JSON.stringify(graph, null, 2);
    if (outFile === '-') process.stdout.write(json + '\n');
    else { fs.writeFileSync(outFile, json); console.error(`wrote ${outFile}`); }
  }
}

// Locate a headless-Chrome binary — prefer the puppeteer cache (already
// installed for the report PDFs), then a system chrome, then chromium.
function findChrome(): string {
  const home = os.homedir();
  const puppeteerDir = path.join(home, '.cache/puppeteer/chrome');
  if (fs.existsSync(puppeteerDir)) {
    // Pick the newest linux-* build.
    const builds = fs.readdirSync(puppeteerDir)
      .filter((d) => d.startsWith('linux-'))
      .sort()
      .reverse();
    for (const b of builds) {
      const bin = path.join(puppeteerDir, b, 'chrome-linux64', 'chrome');
      if (fs.existsSync(bin)) return bin;
    }
  }
  for (const c of ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/snap/bin/chromium']) {
    if (fs.existsSync(c)) return c;
  }
  throw new Error('no chrome/chromium binary found — install one or run scan install-tools');
}

async function renderPng(htmlPath: string, outPng: string, w: number, h: number, settleMs: number): Promise<void> {
  // Chrome's `--screenshot` + `--virtual-time-budget` combo doesn't reliably
  // drive requestAnimationFrame in headless=new, which is what cytoscape's
  // cose-bilkent layout relies on. Puppeteer-core lets us wait on an actual
  // in-page condition (window.__graphReady=true set by cy.one('layoutstop'))
  // then screenshot, which is deterministic.
  const chrome = findChrome();
  const { default: puppeteer } = await import('puppeteer-core');
  const browser = await puppeteer.launch({
    executablePath: chrome,
    args: ['--no-sandbox', '--disable-gpu', '--hide-scrollbars'],
    headless: true,
    defaultViewport: { width: w, height: h },
  });
  try {
    const page = await browser.newPage();
    // Capture in-page console + errors so silent breakage surfaces on stderr.
    page.on('console', (msg) => { if (['error', 'warn'].includes(msg.type())) console.error(`  [page ${msg.type()}] ${msg.text()}`); });
    page.on('pageerror', (err) => console.error(`  [page error] ${err.message}`));
    // Large graphs (thousands of nodes) inline a big JSON literal + take
    // seconds to parse; the default 30s goto is too tight. Give the whole
    // page-load path settleMs + 60s of headroom.
    await page.goto(`file://${path.resolve(htmlPath)}`, { waitUntil: 'load', timeout: settleMs + 60_000 });
    // The page's inline JS sets window.__graphReady=true from a
    // cy.one('layoutstop', …) handler once cose-bilkent has settled and the
    // final cy.fit() has run. Wait for it, with a hard cap.
    await page.waitForFunction('window.__graphReady === true', { timeout: settleMs + 20_000 })
      .catch(() => { /* settle-timeout — screenshot the current state anyway */ });
    // Extra RAF to make sure the final paint has flushed.
    await page.evaluate(`new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => r(null))))`);
    // Diagnostics: report what actually loaded, so silent breakage isn't silent.
    const diag = await page.evaluate(`({
      hasCy: typeof window.cytoscape === 'function',
      graphReady: !!window.__graphReady,
      nodeCount: (window.cy && window.cy.nodes && window.cy.nodes().length) || 0,
      pageErrors: [],
    })`) as { hasCy: boolean; graphReady: boolean; nodeCount: number };
    console.error(`  puppeteer diag: cytoscape=${diag.hasCy} graphReady=${diag.graphReady} nodes=${diag.nodeCount}`);
    await page.screenshot({ path: path.resolve(outPng), fullPage: false, omitBackground: false });
  } finally {
    await browser.close();
  }
}

function renderHtml(graph: unknown, focus: string | null, opts: { forPng?: boolean; inlineJs?: string } = {}): string {
  const title = focus ? `Attack surface — ${focus}` : 'Attack surface — full estate';
  const forPng = !!opts.forPng;
  // For PNG mode: legend is bottom-right (out of the way of the graph), JS is
  // inlined (headless chrome's --virtual-time-budget can't accelerate network
  // fetches — the layout must be able to run against a fully-loaded page).
  const scripts = opts.inlineJs
    ?? '<script src="https://unpkg.com/cytoscape@3.30.2/dist/cytoscape.min.js"></script>\n<script src="https://unpkg.com/cytoscape-cose-bilkent@4.1.0/cytoscape-cose-bilkent.js"></script>';
  return `<!doctype html>
<html><head>
<meta charset="utf-8"><title>${title}</title>
<style>
  html, body { margin: 0; height: 100%; font-family: -apple-system, sans-serif; }
  #cy { width: 100%; height: 100vh; background: #0e1116; }
  #legend { position: fixed; ${forPng ? 'bottom: 12px; right: 12px' : 'top: 10px; left: 10px'}; background: rgba(20,24,32,0.92); color: #eee; padding: 10px 12px; border-radius: 6px; font-size: 12px; line-height: 1.6; z-index: 10; }
  #legend b { color: #fff; }
  .k { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 6px; vertical-align: middle; }
</style>
${scripts}
</head><body>
<div id="cy"></div>
<div id="legend">
  <b>${title}</b><br>
  <span class="k" style="background:#4c9aff"></span>host&nbsp;
  <span class="k" style="background:#ffab00"></span>port&nbsp;
  <span class="k" style="background:#6554c0"></span>tech<br>
  <span class="k" style="background:#e63946"></span>CVE (critical)&nbsp;
  <span class="k" style="background:#ff6b6b"></span>CVE (high)<br>
  <span class="k" style="background:#00875a"></span>DNS peer (MX/NS/CNAME)&nbsp;
  <span class="k" style="background:#f9a825"></span>shared cert
</div>
<script>
const graph = ${JSON.stringify(graph)};
window.cy = cytoscape({
  container: document.getElementById('cy'),
  elements: graph.elements,
  style: [
    { selector: 'node', style: { 'label': 'data(label)', 'color': '#eee', 'font-size': 9, 'text-outline-color': '#0e1116', 'text-outline-width': 2, 'width': 18, 'height': 18 } },
    { selector: 'node[type="host"]', style: { 'background-color': '#4c9aff', 'width': 26, 'height': 26, 'font-size': 11 } },
    { selector: 'node[type="port"]', style: { 'background-color': '#ffab00' } },
    { selector: 'node[type="tech"]', style: { 'background-color': '#6554c0' } },
    { selector: 'node[type="cve"]', style: { 'background-color': '#ff6b6b', 'shape': 'diamond' } },
    { selector: 'node[type="cve"][severity="critical"]', style: { 'background-color': '#e63946', 'width': 22, 'height': 22 } },
    { selector: 'node[type="dns-peer"]', style: { 'background-color': '#00875a', 'shape': 'square' } },
    { selector: 'node[type="cert"]', style: { 'background-color': '#f9a825', 'shape': 'hexagon', 'width': 20, 'height': 20 } },
    { selector: 'edge', style: { 'line-color': '#3a4048', 'width': 0.7, 'opacity': 0.55, 'curve-style': 'bezier', 'target-arrow-shape': 'none' } },
    { selector: 'edge[kind="vulnerable_to"]', style: { 'line-color': '#e63946', 'width': 1.2, 'opacity': 0.8 } },
  ],
  // Built-in cose (no extension needed — clean inline path). Tuning: reduce
  // gravity a bit so the graph spreads; longer edge length gives labels room.
  layout: { name: 'cose', animate: false, fit: true, padding: 60, nodeRepulsion: 200000, idealEdgeLength: 120, gravity: 0.15, componentSpacing: 100 },
  wheelSensitivity: 0.2,
});
window.cy.on('tap', 'node', (e) => { const d = e.target.data(); console.log(d); });
// For static-image render, explicitly re-fit after layout completes then
// hoist a window flag so puppeteer knows to snapshot. Two-frame settle so the
// final paint has flushed before the flag is set. Also fallback-arm the flag
// on a 15s timer so screenshot doesn't hang if layoutstop never fires.
window.cy.one('layoutstop', () => {
  window.cy.fit(undefined, 60);
  requestAnimationFrame(() => requestAnimationFrame(() => { window.__graphReady = true; }));
});
setTimeout(() => { if (!window.__graphReady) { try { window.cy.fit(undefined, 60); } catch(e){} window.__graphReady = true; } }, 15000);
</script>
</body></html>`;
}

main().catch((err: unknown) => {
  console.error('FATAL:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
