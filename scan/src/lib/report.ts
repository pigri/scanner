// Pure per-target report rendering. The report worker gathers a target's rows
// from the DB and hands them here; keeping this pure makes it unit-testable
// without a database.

export interface ReportPort { port: number; protocol: string; service: string | null; product: string | null; version: string | null }
export interface ReportHttp { url: string; status_code: number | null; web_server: string | null; tech: string[] | null }
export interface ReportFinding { severity: string | null; tool: string; title: string; cve: string | null }

export interface TargetReportData {
  target: string;
  generatedAt: string;
  riskScore: number | null;
  ports: ReportPort[];
  http: ReportHttp[];
  findings: ReportFinding[];
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];

function sevRank(sev: string | null): number {
  const i = SEV_ORDER.indexOf((sev ?? 'unknown').toLowerCase());
  return i === -1 ? SEV_ORDER.length : i;
}

/** Slug a target into a filesystem-safe report filename stem. */
export function reportFilename(target: string): string {
  return target.replace(/[^a-zA-Z0-9._-]/g, '_') + '.md';
}

export function renderTargetReport(d: TargetReportData): string {
  const lines: string[] = [];
  lines.push(`# Scan report: ${d.target}`);
  lines.push('');
  lines.push(`- Generated: ${d.generatedAt}`);
  lines.push(`- Risk score: ${d.riskScore ?? 'n/a'}`);
  lines.push(`- Open ports: ${d.ports.length} · HTTP endpoints: ${d.http.length} · Findings: ${d.findings.length}`);
  lines.push('');

  // Findings, most severe first.
  lines.push('## Findings');
  if (!d.findings.length) {
    lines.push('');
    lines.push('_None recorded._');
  } else {
    const sorted = [...d.findings].sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
    lines.push('');
    lines.push('| Severity | Tool | Title | CVE |');
    lines.push('| --- | --- | --- | --- |');
    for (const f of sorted) {
      lines.push(`| ${f.severity ?? 'unknown'} | ${f.tool} | ${f.title.replace(/\|/g, '\\|')} | ${f.cve ?? ''} |`);
    }
  }
  lines.push('');

  // Ports.
  lines.push('## Open ports');
  if (!d.ports.length) {
    lines.push('');
    lines.push('_None recorded._');
  } else {
    lines.push('');
    lines.push('| Port | Proto | Service | Product | Version |');
    lines.push('| --- | --- | --- | --- | --- |');
    for (const p of [...d.ports].sort((a, b) => a.port - b.port)) {
      lines.push(`| ${p.port} | ${p.protocol} | ${p.service ?? ''} | ${p.product ?? ''} | ${p.version ?? ''} |`);
    }
  }
  lines.push('');

  // HTTP endpoints.
  lines.push('## HTTP endpoints');
  if (!d.http.length) {
    lines.push('');
    lines.push('_None recorded._');
  } else {
    lines.push('');
    for (const h of d.http) {
      const tech = h.tech && h.tech.length ? ` — ${h.tech.join(', ')}` : '';
      lines.push(`- \`${h.status_code ?? '???'}\` ${h.url}${h.web_server ? ` (${h.web_server})` : ''}${tech}`);
    }
  }
  lines.push('');

  return lines.join('\n');
}
