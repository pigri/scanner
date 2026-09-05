import { describe, it, expect } from 'vitest';
import { renderTargetReport, reportFilename, type TargetReportData } from '../src/lib/report.js';

const base = (over: Partial<TargetReportData> = {}): TargetReportData => ({
  target: 'host.gov.hu',
  generatedAt: '2026-08-19T12:00:00.000Z',
  riskScore: null,
  ports: [],
  http: [],
  findings: [],
  ...over,
});

describe('reportFilename', () => {
  it('slugs unsafe characters and appends .md', () => {
    expect(reportFilename('a.b.gov.hu')).toBe('a.b.gov.hu.md');
    expect(reportFilename('84.206.102.29')).toBe('84.206.102.29.md');
    // dots are kept (needed for hostnames); path separators become '_' so the
    // result is always a flat, traversal-safe filename.
    expect(reportFilename('weird/../path:x')).toBe('weird_.._path_x.md');
    expect(reportFilename('weird/../path:x')).not.toContain('/');
  });
});

describe('renderTargetReport', () => {
  it('renders the header with counts and risk', () => {
    const md = renderTargetReport(base({ riskScore: 18, ports: [{ port: 443, protocol: 'tcp', service: 'https', product: null, version: null }] }));
    expect(md).toContain('# Scan report: host.gov.hu');
    expect(md).toContain('Risk score: 18');
    expect(md).toContain('Open ports: 1');
  });

  it('shows "None recorded." for empty sections', () => {
    const md = renderTargetReport(base());
    expect(md).toContain('## Findings');
    expect(md.match(/_None recorded._/g)?.length).toBe(3); // findings, ports, http
  });

  it('orders findings most-severe first', () => {
    const md = renderTargetReport(base({
      findings: [
        { severity: 'low', tool: 'nuclei', title: 'low thing', cve: null },
        { severity: 'critical', tool: 'nuclei', title: 'crit thing', cve: 'CVE-2024-1' },
        { severity: 'medium', tool: 'synthesize-eol', title: 'iis old', cve: null },
      ],
    }));
    const iCrit = md.indexOf('crit thing');
    const iMed = md.indexOf('iis old');
    const iLow = md.indexOf('low thing');
    expect(iCrit).toBeLessThan(iMed);
    expect(iMed).toBeLessThan(iLow);
  });

  it('escapes pipes in finding titles so the table stays valid', () => {
    const md = renderTargetReport(base({ findings: [{ severity: 'info', tool: 't', title: 'a | b', cve: null }] }));
    expect(md).toContain('a \\| b');
  });

  it('lists http endpoints with status and tech', () => {
    const md = renderTargetReport(base({ http: [{ url: 'https://host.gov.hu', status_code: 200, web_server: 'nginx', tech: ['Nginx', 'PHP'] }] }));
    expect(md).toContain('`200` https://host.gov.hu (nginx) — Nginx, PHP');
  });
});
