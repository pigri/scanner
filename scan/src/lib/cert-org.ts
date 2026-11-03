// Per-target TLS-certificate Organization (subject O), for the hosts list.
//
// A host can present several certs over time (rotation) and more than one at
// once (RSA + ECDSA). We want the Organization from the most recently seen cert
// that actually carries one, so an OV/EV cert's owner shows even when a later
// self-signed or DV cert (no O) was captured afterwards. Targets with no cert
// Organization at all are absent from the result; callers LEFT JOIN, yielding
// null for them.
//
// Kept as a standalone SELECT (not a fragment) so a test can run the exact
// query against a seeded in-memory DB. ui.ts embeds it as a CTE.
export const CERT_ORG_SQL = `
  SELECT target, organization FROM (
    SELECT target, organization,
           ROW_NUMBER() OVER (PARTITION BY target ORDER BY seen_at DESC, id DESC) rn
    FROM certificates
    WHERE organization IS NOT NULL AND organization != ''
  ) WHERE rn = 1
`;
