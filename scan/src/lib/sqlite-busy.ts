/** True when an error is SQLite lock contention, not a genuine write fault. */
export function isSqliteBusy(e: unknown): boolean {
  if (!e || typeof e !== 'object' || !('code' in e)) return false;
  const code = (e as { code?: unknown }).code;
  return code === 'SQLITE_BUSY' || code === 'SQLITE_BUSY_SNAPSHOT';
}
