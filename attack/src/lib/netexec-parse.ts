export interface NxcRow {
  proto: string;
  target: string;
  user: string;
  pass: string;
  outcome: 'success' | 'fail';
  privilege: string | null;
  raw: string;
}

/**
 * Parse NetExec `[+]`/`[-]` result lines out of stdout. Ignores banner and
 * enumeration lines (`[*]`). Strips ANSI color codes.
 */
export function parseNxcLines(text: string): NxcRow[] {
  const rows: NxcRow[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\x1b\[[0-9;]*m/g, '').trim();
    const m = line.match(/^(\w+)\s+(\S+)\s+\d+\s+\S+\s+\[([+\-])\]\s+(.+)$/);
    if (!m) continue;
    const [, proto, target, sign, payload] = m;
    const cred = payload!.match(/^([^\\]+)\\([^:]+):(\S+)/) || payload!.match(/^(\S+):(\S+)/);
    let user = '';
    let pass = '';
    if (cred) {
      if (cred.length === 4) { user = `${cred[1]}\\${cred[2]}`; pass = cred[3]!; }
      else { user = cred[1]!; pass = cred[2]!; }
    }
    const privMatch = payload!.match(/Pwn3d!|\(admin\)/i);
    rows.push({
      proto: proto!,
      target: target!,
      user,
      pass,
      outcome: sign === '+' ? 'success' : 'fail',
      privilege: privMatch ? privMatch[0] : null,
      raw: line,
    });
  }
  return rows;
}
