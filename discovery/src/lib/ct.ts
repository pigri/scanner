export function expandNameValue(v: string | null | undefined): string[] {
  if (!v) return [];
  return v
    .split('\n')
    .map((s) => s.trim().toLowerCase().replace(/^\*\./, ''))
    .filter(Boolean);
}

interface CrtEntry {
  name_value?: string;
  common_name?: string;
}

interface CertspotterEntry {
  dns_names?: unknown;
}

export function extractCertspotterHosts(response: unknown): string[] {
  if (!Array.isArray(response)) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of response) {
    if (!raw || typeof raw !== 'object') continue;
    const entry = raw as CertspotterEntry;
    if (!Array.isArray(entry.dns_names)) continue;
    for (const name of entry.dns_names) {
      if (typeof name !== 'string') continue;
      const host = name.trim().toLowerCase().replace(/^\*\./, '');
      if (host && !seen.has(host)) {
        seen.add(host);
        out.push(host);
      }
    }
  }
  return out;
}

export function extractCtHosts(response: unknown): string[] {
  if (!Array.isArray(response)) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of response) {
    if (!raw || typeof raw !== 'object') continue;
    const entry = raw as CrtEntry;
    const candidates: string[] = [];
    if (entry.name_value) candidates.push(...expandNameValue(entry.name_value));
    else if (entry.common_name) candidates.push(...expandNameValue(entry.common_name));
    for (const host of candidates) {
      if (!seen.has(host)) {
        seen.add(host);
        out.push(host);
      }
    }
  }
  return out;
}
