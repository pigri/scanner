import { execFile } from 'node:child_process';

/**
 * Resolve a host to its A/AAAA/CNAME answer lines via `dig +short @<resolver>`.
 * Never rejects — a failed/empty lookup resolves to []. Comment lines (dig
 * status lines ending in ';') are stripped. Shared by dns-brute and
 * wildcard-check so both use identical resolution semantics.
 */
export function digShort(host: string, resolver: string, timeoutSec: number): Promise<string[]> {
  return new Promise((resolve) => {
    execFile(
      'dig',
      ['+short', `+time=${timeoutSec}`, '+tries=1', host, `@${resolver}`],
      { timeout: (timeoutSec + 1) * 1000 },
      (_err, stdout) => {
        const lines = (stdout || '')
          .split('\n')
          .map((s) => s.trim())
          .filter((s) => s && !s.endsWith(';'));
        resolve(lines);
      }
    );
  });
}
