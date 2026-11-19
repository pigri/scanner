import type Database from 'better-sqlite3';
import { currentFindingsSelect, findingsRuleOpts } from './current-findings.js';
import { keyOf, type Key } from './resolved.js';

/**
 * Keys (see keyOf) of a target's findings that the shared closing rule calls
 * open. The window-based CLIs (resolved, history) use it so they never call
 * resolved a finding the UI shows as open.
 */
export function openKeysFor(raw: Database.Database, target: string): Set<Key> {
  const rows = raw
    .prepare(
      `SELECT tool, category, title
       FROM (${currentFindingsSelect({ ...findingsRuleOpts(raw), targetParam: '@t' })})
       WHERE resolved = 0`,
    )
    .all({ t: target }) as { tool: string; category: string | null; title: string }[];
  return new Set(rows.map((r) => keyOf({ tool: r.tool, category: r.category ?? '', title: r.title })));
}
