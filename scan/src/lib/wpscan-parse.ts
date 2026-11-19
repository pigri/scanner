/** wpscan --format json prints JSON.pretty_generate output: one key per line, so stdout is one multi-line document. */
export function parseWpscanStdout(stdout: string): unknown {
  const text = stdout.trim();
  // Anything before the document (a stray warning) ends where the first line starting with '{' begins.
  const start = text.startsWith('{') ? 0 : text.search(/^\{/m);
  if (start < 0) throw new Error('no JSON object in wpscan output');
  return JSON.parse(text.slice(start));
}

interface Vuln { title?: string; references?: { cve?: string[] | string } }

export interface WpscanParsed {
  interesting_findings?: { to_s?: string; type?: string; url?: string; references?: unknown }[];
  version?: { number?: string; vulnerabilities?: Vuln[] } | null;
  plugins?: Record<string, { version?: { number?: string } | null; vulnerabilities?: Vuln[] }>;
}

/** wpscan reports CVE ids without the prefix ("2014-4663"), as a list or a single string. */
export function wpscanCve(v: Vuln): string | null {
  const raw = v.references?.cve;
  const first = Array.isArray(raw) ? raw[0] : raw;
  if (typeof first !== 'string' || !first) return null;
  return /^CVE-/i.test(first) ? first.toUpperCase() : `CVE-${first}`;
}
