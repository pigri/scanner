// Single source of truth for resolving the scan SQLite DB path from CLI args.
// The canonical flag is --sqlite (matches every wrapper + scan-all). --db is
// kept as a back-compat alias. Post-processing tools (synthesize-eol, risk,
// query) historically only understood --db, which silently ignored --sqlite and
// fell back to scan.db — this helper prevents that class of bug from recurring.
export const DEFAULT_DB = 'scan.db';

const DB_FLAGS = new Set(['--sqlite', '--db']);

export function isDbFlag(arg: string): boolean {
  return DB_FLAGS.has(arg);
}

/**
 * Scan argv for `--sqlite <path>` or `--db <path>` and return the path.
 * Later occurrences win (last flag on the command line). Falls back to
 * `fallback` (default: scan.db) when neither flag is present.
 */
export function resolveDbArg(argv: string[], fallback: string = DEFAULT_DB): string {
  let result = fallback;
  for (let i = 0; i < argv.length; i++) {
    if (isDbFlag(argv[i]!) && i + 1 < argv.length) result = argv[i + 1]!;
  }
  return result;
}
