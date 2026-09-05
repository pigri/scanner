const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

export function parseTargets(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    if (!seen.has(line)) {
      seen.add(line);
      out.push(line);
    }
  }
  return out;
}

export interface Split {
  hosts: string[];
  ips: string[];
}

export function splitTargets(targets: readonly string[]): Split {
  const hosts: string[] = [];
  const ips: string[] = [];
  for (const t of targets) {
    if (IPV4_RE.test(t) || (t.includes(':') && /^[0-9a-fA-F:]+$/.test(t))) ips.push(t);
    else hosts.push(t);
  }
  return { hosts, ips };
}
