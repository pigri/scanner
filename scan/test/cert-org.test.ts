import { describe, it, expect, beforeEach } from 'vitest';
import { openDb, type Db, type CertInput } from '../src/lib/db.js';
import { CERT_ORG_SQL } from '../src/lib/cert-org.js';

let db: Db;
beforeEach(() => {
  db = openDb(':memory:');
});

let fp = 0;
function cert(o: Partial<CertInput> & { target: string }, seenAt: string): void {
  db.insertCertificate(
    {
      target: o.target,
      port: o.port ?? 443,
      certIndex: o.certIndex ?? 1,
      commonName: o.commonName ?? o.target,
      organization: o.organization ?? null,
      orgUnit: o.orgUnit ?? null,
      locality: o.locality ?? null,
      country: o.country ?? null,
      san: o.san ?? [],
      issuer: o.issuer ?? null,
      notBefore: o.notBefore ?? null,
      notAfter: o.notAfter ?? null,
      keyAlgo: o.keyAlgo ?? null,
      keySize: o.keySize ?? null,
      sigAlgo: o.sigAlgo ?? null,
      serial: o.serial ?? null,
      // distinct fingerprint each call so INSERT OR IGNORE never dedupes a row away
      fingerprintSha256: o.fingerprintSha256 ?? `FP${(fp += 1)}`,
      selfSigned: o.selfSigned ?? false,
    },
    seenAt,
    null,
  );
}

function orgMap(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const r of db.raw.prepare(CERT_ORG_SQL).all() as { target: string; organization: string }[]) {
    out[r.target] = r.organization;
  }
  return out;
}

describe('CERT_ORG_SQL', () => {
  it('picks the latest-by-seen_at non-null Organization per target', () => {
    // rotation: a later cert carries a different org -> newest wins
    cert({ target: 't1.example', organization: 'Old Org' }, '2026-01-01T00:00:00Z');
    cert({ target: 't1.example', organization: 'New Org' }, '2026-06-01T00:00:00Z');
    // latest cert has no org -> fall back to the latest cert that does
    cert({ target: 't2.example', organization: 'Only Org' }, '2026-01-01T00:00:00Z');
    cert({ target: 't2.example', organization: null }, '2026-06-01T00:00:00Z');
    // every cert null -> target absent
    cert({ target: 't3.example', organization: null }, '2026-01-01T00:00:00Z');
    // empty-string org treated as absent
    cert({ target: 't4.example', organization: '' }, '2026-01-01T00:00:00Z');

    const m = orgMap();
    expect(m['t1.example']).toBe('New Org');
    expect(m['t2.example']).toBe('Only Org');
    expect(m['t3.example']).toBeUndefined();
    expect(m['t4.example']).toBeUndefined();
  });

  it('is empty when no certificate carries an Organization', () => {
    cert({ target: 'n.example', organization: null }, '2026-01-01T00:00:00Z');
    expect(db.raw.prepare(CERT_ORG_SQL).all()).toEqual([]);
  });
});
