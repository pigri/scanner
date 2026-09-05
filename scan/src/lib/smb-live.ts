import { type Db } from './db.js';

/** Return targets that our DB has seen listening on 445 (SMB). */
export function smbLiveTargets(db: Db): Set<string> {
  const set = new Set<string>();
  const rows = db.raw.prepare(
    'SELECT DISTINCT target FROM ports WHERE port = 445 OR port = 139'
  ).all() as { target: string }[];
  for (const r of rows) set.add(r.target);
  return set;
}
