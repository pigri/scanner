import { CERT_ORG_SQL } from './cert-org.js';
import { targetAggSql } from './target-agg.js';

// One row per non-URL target for the Targets list (risk_latest never holds URL
// targets, see lib/risk-latest.ts): score and assessment times
// from risk_latest, plus the findings aggregate, cert organization and host
// state. Shared by src/ui.ts and test/target-rows-sql.test.ts (no drift).
/** `coverage` is tableExists(db, 'tool_coverage') at query time. */
export const targetRowsSql = (coverage: boolean): string => `WITH agg AS MATERIALIZED (${targetAggSql(coverage)}),
       certorg AS MATERIALIZED (${CERT_ORG_SQL})
       SELECT rl.target target, rl.score score, rl.created_at, rl.updated_at,
         COALESCE(agg.critical,0) critical, COALESCE(agg.high,0) high, COALESCE(agg.medium,0) medium,
         COALESCE(agg.low,0) low, COALESCE(agg.info,0) info,
         COALESCE(agg.findings,0) findings, COALESCE(agg.cves,0) cves,
         COALESCE(agg.versionMatch,0) versionMatch,
         certorg.organization organization,
         COALESCE(host_state.active,1) active
       FROM risk_latest rl
       LEFT JOIN agg ON agg.target = rl.target
       LEFT JOIN certorg ON certorg.target = rl.target
       LEFT JOIN host_state ON host_state.target = rl.target`;

/** Startup message when the UI's DB has no risk_latest table, else null. */
export function riskLatestMissingMessage(hasTable: boolean): string | null {
  return hasTable
    ? null
    : 'risk_latest table is missing from the scan DB. The UI opens the DB read-only and cannot create it: open the DB once with any scan tool to migrate, then restart the UI.';
}
