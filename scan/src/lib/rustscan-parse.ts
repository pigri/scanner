export interface RustscanHit { ip: string; port: number }

/**
 * Parse rustscan `--greppable` stdout, extracting `ip -> [ports]` lines.
 * Silently drops non-numeric ports (e.g. `[22,foo,80]` → `[22, 80]`).
 */
export function parseRustscanStdout(text: string): RustscanHit[] {
  const hits: RustscanHit[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    const m = line.match(/^([a-z0-9._:-]+)\s*->\s*\[([^\]]*)\]/i);
    if (!m) continue;
    const ip = m[1]!;
    for (const p of m[2]!.split(',')) {
      const port = parseInt(p.trim(), 10);
      if (Number.isFinite(port) && port >= 0 && port <= 65535) {
        hits.push({ ip, port });
      }
    }
  }
  return hits;
}
