#!/usr/bin/env -S node --loader tsx
import fs from 'node:fs';
import path from 'node:path';
import { buildGraph, type EnrichedRow, type Graph } from './lib/graph.js';
import { openDb, readEnrichedFromDb } from './lib/db.js';

interface Opts {
  input: string | null;
  sqlite: string | null;
  since: string | null;
  until: string | null;
  out: string;
  title: string | null;
  help?: boolean;
}

function normalizeDate(v: string, boundary: 'start' | 'end'): string {
  // date-only: extend to full-day ISO; already-ISO passes through.
  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) {
    return boundary === 'start' ? `${v}T00:00:00.000Z` : `${v}T23:59:59.999Z`;
  }
  return v;
}

function parseArgs(argv: string[]): Opts {
  const opts: Opts = { input: null, sqlite: null, since: null, until: null, out: 'graph.html', title: null };
  const rest: string[] = [];
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i]!;
    if (a === '-o' || a === '--out') opts.out = next();
    else if (a === '--title') opts.title = next();
    else if (a === '--sqlite') opts.sqlite = next();
    else if (a === '--since') opts.since = normalizeDate(next(), 'start');
    else if (a === '--until') opts.until = normalizeDate(next(), 'end');
    else if (a === '-h' || a === '--help') opts.help = true;
    else rest.push(a);
  }
  if (rest[0]) opts.input = rest[0];
  return opts;
}

function usage(): void {
  console.error(`Usage: visualize [<enriched.jsonl>] [--sqlite recon.db] [options]

Two input modes:
  --sqlite recon.db     Read from SQLite backing store (recommended)
  <enriched.jsonl>      Read from a per-domain JSONL file

Date filters (SQLite mode only):
  --since <iso>         Only include resolutions seen at/after this ISO date
  --until <iso>         Only include resolutions seen at/before this ISO date

Output:
  -o graph.html         Self-contained HTML dashboard (default: graph.html)
  --title "..."         Header title

Examples:
  visualize --sqlite recon.db --title 'current'
  visualize --sqlite recon.db --since 2026-08-19 --title 'new today'
  visualize enriched.jsonl -o graph.html                   # legacy JSONL mode
`);
}

function escapeHtml(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) => {
    const map: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
    return map[c] ?? c;
  });
}

function render(graph: Graph, title: string): string {
  const data = JSON.stringify(graph);
  const t = title;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(t)}</title>
<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<style>
  :root {
    --bg: #f5f6f8; --surface: #fff; --border: #d5d9e0;
    --text: #1a1d23; --text2: #5a6178; --text3: #8b92a5;
    --accent: #006fff; --green: #16a34a; --purple: #9333ea;
    --orange: #d97706; --red: #dc2626; --cyan: #0891b2;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #0f1115; --surface: #171a20; --border: #2b303a;
            --text: #e8eaed; --text2: #a8b0bd; --text3: #6b7280; }
  }
  html, body { margin: 0; background: var(--bg); color: var(--text);
               font: 14px/1.5 -apple-system, system-ui, sans-serif; }
  header { padding: 16px 24px; border-bottom: 1px solid var(--border); background: var(--surface); }
  header h1 { margin: 0; font-size: 18px; }
  header .stats { color: var(--text2); font-size: 13px; margin-top: 4px; }
  nav { display: flex; gap: 4px; padding: 8px 24px; background: var(--surface);
        border-bottom: 1px solid var(--border); }
  nav button { background: transparent; border: 1px solid transparent; color: var(--text2);
               padding: 6px 12px; border-radius: 6px; cursor: pointer; font: inherit; }
  nav button:hover { background: var(--bg); color: var(--text); }
  nav button.active { background: var(--bg); color: var(--text); border-color: var(--border); }
  main { padding: 16px 24px; }
  .view { display: none; }
  .view.active { display: block; }
  #net { height: calc(100vh - 200px); background: var(--surface); border: 1px solid var(--border); border-radius: 8px; }
  .filters { display: flex; gap: 12px; margin-bottom: 12px; align-items: center; flex-wrap: wrap; color: var(--text2); }
  .filters label { display: flex; align-items: center; gap: 6px; }
  .chart-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; }
  .chart-wrap h2 { margin: 0 0 12px; font-size: 15px; }
  canvas { max-width: 100%; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); }
  th { color: var(--text2); font-weight: 500; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .legend { display: flex; gap: 16px; margin-top: 8px; font-size: 12px; color: var(--text2); flex-wrap: wrap; }
  .legend span { display: inline-flex; align-items: center; gap: 6px; }
  .swatch { display: inline-block; width: 12px; height: 12px; border-radius: 2px; border: 1px solid rgba(0,0,0,0.2); }
</style>
</head>
<body>
<header>
  <h1>${escapeHtml(t)}</h1>
  <div class="stats" id="stats"></div>
</header>
<nav>
  <button data-view="findings" class="active">Findings</button>
  <button data-view="net">Network</button>
  <button data-view="asn">ASN distribution</button>
  <button data-view="country">Country</button>
  <button data-view="shared">Shared IPs</button>
</nav>
<main>
  <section id="view-findings" class="view active">
    <div class="chart-wrap">
      <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center">
        <input type="search" id="findingsSearch" placeholder="Search domain, IP, PTR, ASN, org, country..." autocomplete="off" style="flex:1;min-width:300px;padding:8px 10px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text)">
        <select id="findingsAsn" style="padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text)">
          <option value="">any ASN</option>
        </select>
        <select id="findingsCountry" style="padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text)">
          <option value="">any country</option>
        </select>
        <label><input type="checkbox" id="findingsPtrDiffers"> PTR differs from domain</label>
        <label><input type="checkbox" id="findingsSharedOnly"> shared IPs only</label>
        <span id="findingsCount" style="color:var(--text2);font-size:12px;margin-left:auto"></span>
      </div>
      <div style="overflow:auto;max-height:calc(100vh - 260px)">
        <table id="findingsTable">
          <thead style="position:sticky;top:0;background:var(--surface);z-index:1"><tr>
            <th data-sort="domain">domain</th>
            <th data-sort="ip">IP</th>
            <th data-sort="ptr">PTR</th>
            <th data-sort="asn">ASN</th>
            <th data-sort="country">country</th>
            <th data-sort="shared" class="num">shared</th>
          </tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </div>
  </section>
  <section id="view-net" class="view">
    <div class="filters">
      <label style="flex:1;min-width:220px"><input type="search" id="netSearch" placeholder="Search domain / IP / ASN..." autocomplete="off" style="width:100%;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text)"></label>
      <label><input type="checkbox" id="showDomains" checked> domains</label>
      <label><input type="checkbox" id="showIps" checked> IPs</label>
      <label><input type="checkbox" id="showAsns" checked> ASNs</label>
      <label>min domains per IP: <input type="number" id="minDomains" value="1" min="1" style="width:60px"></label>
      <label>physics <input type="checkbox" id="physics" checked></label>
      <span id="searchStatus" style="color:var(--text2);font-size:12px"></span>
    </div>
    <div class="legend">
      <span><span class="swatch" style="background:#006fff"></span> domain</span>
      <span><span class="swatch" style="background:#d97706"></span> IP</span>
      <span><span class="swatch" style="background:#9333ea"></span> ASN</span>
      <span>node size = degree</span>
    </div>
    <div id="net"></div>
  </section>
  <section id="view-asn" class="view">
    <div class="chart-wrap"><h2>IPs per ASN</h2><canvas id="asnIpChart" height="380"></canvas></div>
    <div class="chart-wrap"><h2>Domains per ASN</h2><canvas id="asnDomainChart" height="380"></canvas></div>
  </section>
  <section id="view-country" class="view">
    <div class="chart-wrap"><h2>IPs by country</h2><canvas id="countryChart" height="300"></canvas></div>
  </section>
  <section id="view-shared" class="view">
    <div class="chart-wrap">
      <h2>IPs hosting multiple domains</h2>
      <input type="search" id="sharedSearch" placeholder="Filter rows..." autocomplete="off" style="width:100%;padding:6px 8px;margin-bottom:8px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text)">
      <table id="sharedTable">
        <thead><tr><th>IP</th><th class="num">#domains</th><th>ASN</th><th>country</th><th>domains</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </section>
</main>
<script>
const DATA = ${data};
document.getElementById('stats').textContent =
  DATA.domains.length + ' domains · ' + DATA.ips.length + ' IPs · ' +
  DATA.asns.length + ' ASNs · ' + DATA.countries.length + ' countries';

document.querySelectorAll('nav button').forEach(b => {
  b.addEventListener('click', () => {
    document.querySelectorAll('nav button').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.view').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    document.getElementById('view-' + b.dataset.view).classList.add('active');
  });
});

let network = null;
function buildNetwork() {
  const showDomains = document.getElementById('showDomains').checked;
  const showIps = document.getElementById('showIps').checked;
  const showAsns = document.getElementById('showAsns').checked;
  const minDomains = parseInt(document.getElementById('minDomains').value, 10) || 1;
  const physics = document.getElementById('physics').checked;

  const nodes = [];
  const edges = [];
  const ipSet = new Set();

  for (const ip of DATA.ips) {
    if (ip.domains.length < minDomains) continue;
    ipSet.add(ip.ip);
    if (showIps) {
      const ptrs = (ip.ptr || []).join(', ');
      nodes.push({
        id: 'ip:' + ip.ip, label: ip.ip, group: 'ip',
        title: ip.ip +
          (ptrs ? '\\nPTR: ' + ptrs : '') +
          '\\n' + (ip.as_name || '') +
          '\\n' + (ip.country || '') +
          '\\n' + ip.domains.length + ' domains',
        value: Math.max(3, ip.domains.length),
      });
    }
  }
  for (const d of DATA.domains) {
    const linked = (d.addresses || []).filter(a => ipSet.has(a.ip));
    if (!linked.length) continue;
    if (showDomains) nodes.push({ id: 'd:' + d.domain, label: d.domain, group: 'domain', title: d.domain, value: 1 });
    if (showIps && showDomains) for (const a of linked) edges.push({ from: 'd:' + d.domain, to: 'ip:' + a.ip });
  }
  for (const asn of DATA.asns) {
    const linkedIps = asn.ips.filter(ip => ipSet.has(ip));
    if (!linkedIps.length) continue;
    if (showAsns) {
      nodes.push({
        id: 'a:' + asn.asn, label: asn.asn + '\\n' + (asn.as_name || '').slice(0, 30), group: 'asn',
        title: asn.asn + ' — ' + (asn.as_name || '') + '\\n' + asn.ips.length + ' IPs · ' + asn.domains.length + ' domains',
        value: Math.max(5, asn.ips.length),
      });
    }
    if (showAsns && showIps) for (const ip of linkedIps) edges.push({ from: 'ip:' + ip, to: 'a:' + asn.asn });
    if (showAsns && !showIps && showDomains) for (const dm of asn.domains) edges.push({ from: 'd:' + dm, to: 'a:' + asn.asn });
  }

  const opts = {
    nodes: { shape: 'dot', font: { color: getComputedStyle(document.body).color, size: 11 },
             borderWidth: 1, scaling: { min: 4, max: 40 } },
    edges: { color: { color: '#8b92a5', opacity: 0.35 }, width: 0.5, smooth: false },
    groups: {
      domain: { color: { background: '#006fff', border: '#0057c9' } },
      ip:     { color: { background: '#d97706', border: '#b45309' }, shape: 'square' },
      asn:    { color: { background: '#9333ea', border: '#6d28d9' }, shape: 'hexagon' },
    },
    physics: {
      enabled: physics,
      forceAtlas2Based: { gravitationalConstant: -30, springLength: 100, springConstant: 0.05 },
      solver: 'forceAtlas2Based', stabilization: { iterations: 200 },
    },
    interaction: { hover: true, tooltipDelay: 100 },
  };
  if (network) network.destroy();
  network = new vis.Network(document.getElementById('net'), { nodes, edges }, opts);
}
document.querySelectorAll('#view-net input:not([type="search"])').forEach(el => el.addEventListener('change', buildNetwork));
buildNetwork();

const netSearch = document.getElementById('netSearch');
const searchStatus = document.getElementById('searchStatus');
let searchTimer = null;
netSearch.addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(runNetSearch, 150);
});
netSearch.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') { netSearch.value = ''; runNetSearch(); }
  if (e.key === 'Enter') runNetSearch();
});

function runNetSearch() {
  const q = netSearch.value.trim().toLowerCase();
  if (!network) return;
  const allNodes = network.body.data.nodes;
  const allEdges = network.body.data.edges;
  const nodeIds = allNodes.getIds();
  if (!q) {
    allNodes.update(nodeIds.map(id => ({ id, hidden: false, borderWidth: 1, size: undefined })));
    allEdges.update(allEdges.getIds().map(id => ({ id, hidden: false })));
    searchStatus.textContent = '';
    network.unselectAll();
    return;
  }
  const matches = new Set();
  for (const id of nodeIds) {
    const n = allNodes.get(id);
    const hay = ((n.label || '') + ' ' + (n.title || '')).toLowerCase();
    if (hay.includes(q)) matches.add(id);
  }
  const visible = new Set(matches);
  const edgeUpdates = [];
  for (const eid of allEdges.getIds()) {
    const e = allEdges.get(eid);
    const from = e.from, to = e.to;
    const touchesMatch = matches.has(from) || matches.has(to);
    if (touchesMatch) {
      visible.add(from); visible.add(to);
      edgeUpdates.push({ id: eid, hidden: false });
    } else {
      edgeUpdates.push({ id: eid, hidden: true });
    }
  }
  allEdges.update(edgeUpdates);
  allNodes.update(nodeIds.map(id => ({
    id,
    hidden: !visible.has(id),
    borderWidth: matches.has(id) ? 4 : 1,
    size: matches.has(id) ? 20 : undefined,
  })));
  searchStatus.textContent = matches.size + ' match' + (matches.size === 1 ? '' : 'es') +
    ' + ' + (visible.size - matches.size) + ' neighbor' + (visible.size - matches.size === 1 ? '' : 's');
  if (matches.size) {
    network.selectNodes([...matches]);
    network.fit({ nodes: [...matches].slice(0, 50), animation: { duration: 400 } });
  }
}

function barChart(canvasId, labels, data, label, color) {
  return new Chart(document.getElementById(canvasId), {
    type: 'bar',
    data: { labels, datasets: [{ label, data, backgroundColor: color, borderColor: color, borderWidth: 1 }] },
    options: {
      indexAxis: 'y', responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(139,146,165,0.15)' }, ticks: { color: getComputedStyle(document.body).color } },
        y: { grid: { display: false }, ticks: { color: getComputedStyle(document.body).color, autoSkip: false } },
      },
    },
  });
}

const asnByIps = [...DATA.asns].sort((a, b) => b.ips.length - a.ips.length).slice(0, 20);
barChart('asnIpChart',
  asnByIps.map(a => a.asn + ' ' + (a.as_name || '').slice(0, 40)),
  asnByIps.map(a => a.ips.length),
  'IPs', 'rgba(217, 119, 6, 0.7)');

const asnByDomains = [...DATA.asns].sort((a, b) => b.domains.length - a.domains.length).slice(0, 20);
barChart('asnDomainChart',
  asnByDomains.map(a => a.asn + ' ' + (a.as_name || '').slice(0, 40)),
  asnByDomains.map(a => a.domains.length),
  'domains', 'rgba(147, 51, 234, 0.7)');

barChart('countryChart', DATA.countries.map(c => c.cc), DATA.countries.map(c => c.n),
  'IPs', 'rgba(0, 111, 255, 0.7)');

// ---- Findings table ----
const findingsRows = [];
for (const d of DATA.domains) {
  for (const a of (d.addresses || [])) {
    const ipInfo = DATA.ips.find(x => x.ip === a.ip);
    const ptrs = (a.ptr || []).join(', ');
    const shared = ipInfo ? ipInfo.domains.length : 1;
    findingsRows.push({
      domain: d.domain,
      ip: a.ip,
      ptr: ptrs,
      asn: a.asn || '',
      as_name: a.as_name || '',
      country: a.country_code || '',
      shared,
    });
  }
}

const asnSet = new Set(findingsRows.map(r => r.asn).filter(Boolean));
const asnSel = document.getElementById('findingsAsn');
[...asnSet].sort().forEach(a => {
  const opt = document.createElement('option');
  opt.value = a; opt.textContent = a;
  asnSel.appendChild(opt);
});
const countrySet = new Set(findingsRows.map(r => r.country).filter(Boolean));
const countrySel = document.getElementById('findingsCountry');
[...countrySet].sort().forEach(c => {
  const opt = document.createElement('option');
  opt.value = c; opt.textContent = c;
  countrySel.appendChild(opt);
});

const findingsBody = document.querySelector('#findingsTable tbody');
const findingsSearch = document.getElementById('findingsSearch');
const findingsPtrDiffers = document.getElementById('findingsPtrDiffers');
const findingsSharedOnly = document.getElementById('findingsSharedOnly');
const findingsCount = document.getElementById('findingsCount');
let sortKey = 'domain', sortDir = 1;

function renderFindings() {
  const q = findingsSearch.value.trim().toLowerCase();
  const asn = asnSel.value;
  const country = countrySel.value;
  const ptrDiffers = findingsPtrDiffers.checked;
  const sharedOnly = findingsSharedOnly.checked;
  const filtered = findingsRows.filter(r => {
    if (asn && r.asn !== asn) return false;
    if (country && r.country !== country) return false;
    if (sharedOnly && r.shared < 2) return false;
    if (ptrDiffers) {
      const ptrList = r.ptr.split(',').map(s => s.trim().toLowerCase());
      if (!r.ptr || ptrList.includes(r.domain.toLowerCase())) return false;
    }
    if (!q) return true;
    return (r.domain + ' ' + r.ip + ' ' + r.ptr + ' ' + r.asn + ' ' + r.as_name + ' ' + r.country).toLowerCase().includes(q);
  });
  filtered.sort((a, b) => {
    const av = a[sortKey], bv = b[sortKey];
    if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * sortDir;
    return String(av).localeCompare(String(bv)) * sortDir;
  });
  const limit = 500;
  const shown = filtered.slice(0, limit);
  findingsBody.innerHTML = shown.map(r =>
    '<tr>' +
    '<td>' + esc(r.domain) + '</td>' +
    '<td>' + esc(r.ip) + '</td>' +
    '<td style="color:var(--text2)">' + esc(r.ptr) + '</td>' +
    '<td>' + esc(r.asn) + '</td>' +
    '<td>' + esc(r.country) + '</td>' +
    '<td class="num">' + r.shared + '</td>' +
    '</tr>'
  ).join('');
  findingsCount.textContent = filtered.length + '/' + findingsRows.length +
    (filtered.length > limit ? ' (first ' + limit + ' shown)' : '');
}
findingsSearch.addEventListener('input', renderFindings);
asnSel.addEventListener('change', renderFindings);
countrySel.addEventListener('change', renderFindings);
findingsPtrDiffers.addEventListener('change', renderFindings);
findingsSharedOnly.addEventListener('change', renderFindings);
document.querySelectorAll('#findingsTable thead th').forEach(th => {
  th.style.cursor = 'pointer';
  th.addEventListener('click', () => {
    const k = th.dataset.sort;
    if (!k) return;
    if (sortKey === k) sortDir = -sortDir;
    else { sortKey = k; sortDir = 1; }
    renderFindings();
  });
});
renderFindings();

// ---- Shared IPs table (unchanged below) ----
const sharedRows = DATA.ips.filter(ip => ip.domains.length > 1).sort((a, b) => b.domains.length - a.domains.length);
const tbody = document.querySelector('#sharedTable tbody');
for (const ip of sharedRows) {
  const tr = document.createElement('tr');
  const domainsFull = ip.domains.join(' ');
  tr.dataset.hay = (ip.ip + ' ' + (ip.asn || '') + ' ' + (ip.as_name || '') + ' ' + (ip.country_code || '') + ' ' + domainsFull).toLowerCase();
  tr.innerHTML =
    '<td>' + ip.ip + '</td>' +
    '<td class="num">' + ip.domains.length + '</td>' +
    '<td>' + (ip.asn || '') + ' ' + esc((ip.as_name || '').slice(0, 40)) + '</td>' +
    '<td>' + (ip.country_code || '') + '</td>' +
    '<td>' + ip.domains.slice(0, 12).map(esc).join(', ') +
    (ip.domains.length > 12 ? ' … +' + (ip.domains.length - 12) : '') + '</td>';
  tbody.appendChild(tr);
}
const sharedSearch = document.getElementById('sharedSearch');
sharedSearch.addEventListener('input', () => {
  const q = sharedSearch.value.trim().toLowerCase();
  for (const tr of tbody.querySelectorAll('tr')) {
    tr.style.display = !q || tr.dataset.hay.includes(q) ? '' : 'none';
  }
});
function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}
</script>
</body>
</html>`;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  if (opts.help || (!opts.input && !opts.sqlite)) {
    usage();
    process.exit(opts.input || opts.sqlite ? 0 : 1);
  }

  let rows: EnrichedRow[];
  let sourceLabel: string;
  if (opts.sqlite) {
    const db = openDb(opts.sqlite);
    rows = readEnrichedFromDb(db, { since: opts.since, until: opts.until });
    db.close();
    const range = opts.since || opts.until
      ? ` [${opts.since ?? '…'} → ${opts.until ?? '…'}]`
      : '';
    sourceLabel = `sqlite ${path.basename(opts.sqlite)}${range}`;
  } else {
    rows = fs
      .readFileSync(opts.input!, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l) as EnrichedRow);
    sourceLabel = `jsonl ${path.basename(opts.input!)}`;
  }

  const graph = buildGraph(rows);
  const defaultTitle = `Recon: ${sourceLabel}`;
  const html = render(graph, opts.title ?? defaultTitle);
  fs.writeFileSync(opts.out, html);
  console.error(`wrote ${opts.out}`);
  console.error(`  source: ${sourceLabel}`);
  console.error(
    `  ${graph.domains.length} domains · ${graph.ips.length} IPs · ${graph.asns.length} ASNs · ${graph.countries.length} countries`
  );
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  console.error('FATAL:', msg);
  process.exit(1);
});
