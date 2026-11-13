import { CERT_ORG_SQL } from './cert-org.js';
import { NO_URL } from './risk-latest.js';
import { TARGET_AGG_SQL } from './target-agg.js';

// One row per non-URL target for the Targets list: score and assessment times
// from risk_latest, plus the findings aggregate, cert organization and host
// state. Shared by src/ui.ts and test/target-rows-sql.test.ts (no drift).
export const TARGET_ROWS_SQL = `WITH agg AS MATERIALIZED (${TARGET_AGG_SQL}),
       certorg AS MATERIALIZED (${CERT_ORG_SQL})
       SELECT rl.target target, rl.score score, rl.created_at, rl.updated_at,
         COALESCE(agg.critical,0) critical, COALESCE(agg.high,0) high, COALESCE(agg.medium,0) medium,
         COALESCE(agg.low,0) low, COALESCE(agg.info,0) info,
         COALESCE(agg.findings,0) findings, COALESCE(agg.cves,0) cves,
         COALESCE(agg.versionMatch,0) versionMatch,
         certorg.organization organization,
         COALESCE(host_state.active,1) active
       FROM (SELECT * FROM risk_latest WHERE ${NO_URL}) rl
       LEFT JOIN agg ON agg.target = rl.target
       LEFT JOIN certorg ON certorg.target = rl.target
       LEFT JOIN host_state ON host_state.target = rl.target`;

/** Startup message when the UI's DB has no risk_latest table, else null. */
export function riskLatestMissingMessage(hasTable: boolean): string | null {
  return hasTable
    ? null
    : 'risk_latest table is missing from the scan DB. The UI opens the DB read-only and cannot create it: open the DB once with any scan tool to migrate, then restart the UI.';
}
