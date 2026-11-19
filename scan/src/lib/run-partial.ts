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
