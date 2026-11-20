import type { Db, RunFinish } from './db.js';

/**
 * A run is partial when something failed and rows were written under its stamp.
 * Rule 3 reads MAX(seen_at) per (target, tool) as proof the tool saw the target
 * again; a failure that wrote no rows moves no watermark, so only the
 * rows-and-failure combination can close older findings by mistake.
 */
export function rowsAtRisk(rows: number, failed: boolean): boolean {
  return rows > 0 && failed;
}

/** Targets that stored rows in this run but are not in `covered`: their new rows move the rule-3 watermark. */
export function incompleteHosts(rowsByTarget: ReadonlyMap<string, number>, covered: ReadonlySet<string>): number {
  let n = 0;
  for (const [t, rows] of rowsByTarget) if (rowsAtRisk(rows, !covered.has(t))) n++;
  return n;
}

/** A failure the wrapper counts: a number names a count, a boolean a single event. */
export type Signal = readonly [value: number | boolean, label: string];

/** The `why` list for the finish note, in the order given. Zero and false drop out. */
export function partialReasons(signals: readonly Signal[]): string[] {
  const out: string[] = [];
  for (const [v, label] of signals) {
    if (typeof v === 'number') { if (v > 0) out.push(`${v} ${label}`); }
    else if (v) out.push(label);
  }
  return out;
}

/** The `partial run: ...` note, or undefined for a complete run. */
export function partialNote(why: readonly string[]): string | undefined {
  return why.length ? `partial run: ${why.join(', ')}` : undefined;
}

/** `partial` and `notes` for a finish line; `notes` joins any note the wrapper already has. */
export function partialFinish(why: readonly string[], notes: readonly string[] = []): Pick<RunFinish, 'partial' | 'notes'> {
  const all = [...notes];
  const n = partialNote(why);
  if (n) all.push(n);
  return { partial: why.length > 0, ...(all.length ? { notes: all.join('; ') } : {}) };
}

/** Exit code of a tool that must exit 0 to count as complete. -1 is a timeout kill. */
export function exitFailed(code: number): boolean {
  return code !== 0;
}

/** `exit N` for the note; a kill by the wrapper's timeout reads as such. */
export function exitReason(code: number): string {
  return code === -1 ? 'killed on timeout' : `exit ${code}`;
}

/** finishRun with `partial` and the note derived from `why`. */
export function finishWithWhy(db: Db, id: number, f: Omit<RunFinish, 'partial'>, why: readonly string[]): void {
  const extra = f.notes ? [f.notes] : [];
  db.finishRun(id, { ...f, ...partialFinish(why, extra) });
}

/**
 * testssl 3.2 turns a failed connectivity check into a FATAL scanProblem record
 * and exits 246 (ERR_*, 242 and up); its EXIT trap still closes the JSON, so the
 * file parses although the vulnerability checks never ran.
 */
export function testsslAborted(findings: unknown, code: number): boolean {
  if (code >= 242) return true;
  if (!Array.isArray(findings)) return false;
  return findings.some((f: unknown) => {
    const r = f as { id?: unknown; severity?: unknown; finding?: unknown } | null;
    if (!r) return false;
    return (r.id === 'scanProblem' && r.severity === 'FATAL')
      || (r.id === 'scanTime' && r.finding === 'Scan interrupted');
  });
}

const NO_TOKEN_PREFIX = 'No WPScan API Token given';

/**
 * wpscan (cms_scanner) exits 0 clean and 5 when vulnerable; 1 to 4 are CLI error,
 * interrupt, exception and unfinished scan. A scan_aborted key can accompany exit 0.
 * An empty vuln_api reply (429, http error, exhausted quota) leaves the vulnerability
 * rows missing while the exit stays 0. The no-token notice is not a failure: the run
 * is deliberately without the vuln API.
 */
export function wpscanFailed(code: number, parsed: unknown): boolean {
  if (code !== 0 && code !== 5) return true;
  const p = parsed as { scan_aborted?: unknown; vuln_api?: { error?: unknown; http_error?: unknown; requests_remaining?: unknown } } | null;
  if (!p || typeof p !== 'object') return false;
  if (p.scan_aborted !== undefined) return true;
  const api = p.vuln_api;
  if (!api || typeof api !== 'object') return false;
  const noToken = typeof api.error === 'string' && api.error.startsWith(NO_TOKEN_PREFIX);
  return (api.error !== undefined && !noToken) || api.http_error !== undefined || api.requests_remaining === 0;
}
