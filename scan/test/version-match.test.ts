import { describe, it, expect } from 'vitest';
import type { CpeMatchRow, CveMeta, VulnLookup } from '../src/lib/nvd-db.js';
import { resolveAlias } from '../src/lib/cpe-aliases.js';
import {
  parseVersion, compareVersions, inRange, normalizeVersion,
  parseServerHeader, parseTechToken, evidenceFromPort, matchCves,
  severityForCvss, type Evidence,
} from '../src/lib/version-match.js';

const BANNER = 'Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/8.0.30';

function row(over: Partial<CpeMatchRow> & { cve_id: string }): CpeMatchRow {
  return {
    vendor: 'apache', product: 'http_server', version: '*', update_: '*',
    start_incl: null, start_excl: null, end_incl: null, end_excl: null, ...over,
  };
}

function fake(rows: CpeMatchRow[], meta: Record<string, number | null> = {}): VulnLookup {
  return {
    snapshotAt: '2026-11-01T00:00:00.000Z',
    cpeMatches: (v, p) => rows.filter((r) => r.vendor === v && r.product === p),
    cveMeta: (ids) => {
      const m = new Map<string, CveMeta>();
      for (const id of ids) {
        const cvss = id in meta ? meta[id]! : 7.5;
        m.set(id, { cvss, cvss_version: cvss === null ? null : '3.1', published: null, last_modified: null });
      }
      return m;
    },
  };
}

describe('parseVersion / compareVersions', () => {
  it('splits numeric and alpha segments', () => {
    expect(parseVersion('1.0.2k')).toEqual([1, 0, 2, 'k']);
    expect(parseVersion('9.3p1')).toEqual([9, 3, 'p', 1]);
  });
  it('orders numerically, not lexically', () => {
    expect(compareVersions('2.4.10', '2.4.9')).toBeGreaterThan(0);
    expect(compareVersions('2.4.6', '2.4.6')).toBe(0);
    expect(compareVersions('2.4', '2.4.0')).toBe(0);
  });
  it('orders a letter suffix after its base release', () => {
    expect(compareVersions('1.0.2k', '1.0.2')).toBeGreaterThan(0);
    expect(compareVersions('1.0.2k', '1.0.2u')).toBeLessThan(0);
    expect(compareVersions('1.0.2k', '1.0.3')).toBeLessThan(0);
  });
});

describe('normalizeVersion', () => {
  it('strips the build suffix after a dash', () => {
    expect(normalizeVersion('1.0.2k-fips')).toBe('1.0.2k');
  });
  it('needs at least two numeric segments', () => {
    expect(normalizeVersion('2')).toBeNull();
    expect(normalizeVersion('v3')).toBeNull();
    expect(normalizeVersion('2.4')).toBe('2.4');
    expect(normalizeVersion('9.3p1')).toBe('9.3p1');
  });
});

describe('inRange', () => {
  const r = (o: Partial<CpeMatchRow>) => row({ cve_id: 'X', ...o });
  it('start_incl is inclusive, end_excl exclusive', () => {
    const rr = r({ start_incl: '2.4.0', end_excl: '2.4.10' });
    expect(inRange('2.4.0', rr)).toBe(true);
    expect(inRange('2.4.9', rr)).toBe(true);
    expect(inRange('2.4.10', rr)).toBe(false);
    expect(inRange('2.3.9', rr)).toBe(false);
  });
  it('start_excl is exclusive, end_incl inclusive', () => {
    const rr = r({ start_excl: '2.4.0', end_incl: '2.4.10' });
    expect(inRange('2.4.0', rr)).toBe(false);
    expect(inRange('2.4.10', rr)).toBe(true);
    expect(inRange('2.4.11', rr)).toBe(false);
  });
  it('handles an alpha end bound', () => {
    const rr = r({ start_incl: '1.0.2', end_incl: '1.0.2u' });
    expect(inRange('1.0.2k', rr)).toBe(true);
    expect(inRange('1.0.2v', rr)).toBe(false);
  });
  it('a row with no bounds is not a range', () => {
    expect(inRange('1.0', r({}))).toBe(false);
  });
});

describe('parseServerHeader', () => {
  it('parses the incident banner', () => {
    const ev = parseServerHeader(BANNER);
    expect(ev.map((e) => [e.name, e.version, e.raw])).toEqual([
      ['Apache', '2.4.6', '2.4.6'],
      ['OpenSSL', '1.0.2k', '1.0.2k-fips'],
      ['PHP', '8.0.30', '8.0.30'],
    ]);
    expect(ev.every((e) => e.distro === 'CentOS')).toBe(true);
  });
  it('has no distro when none is named', () => {
    expect(parseServerHeader('nginx/1.25.3')[0]!.distro).toBeNull();
  });
  it('drops tokens without a version', () => {
    expect(parseServerHeader('cloudflare')).toEqual([]);
  });
});

describe('parseTechToken', () => {
  it('parses the httpx label forms', () => {
    expect(parseTechToken('Apache HTTP Server:2.4.6')).toMatchObject({ name: 'Apache HTTP Server', version: '2.4.6' });
    expect(parseTechToken('OpenSSL:1.0.2k')).toMatchObject({ name: 'OpenSSL', version: '1.0.2k' });
    expect(parseTechToken('PHP:8.0.30')).toMatchObject({ name: 'PHP', version: '8.0.30' });
  });
  it('returns null when there is no version', () => {
    expect(parseTechToken('jQuery')).toBeNull();
  });
});

describe('evidenceFromPort', () => {
  it('reads product, version and distro from nmap fields', () => {
    const e = evidenceFromPort('OpenSSH', '7.4', 'protocol 2.0');
    expect(e).toMatchObject({ name: 'OpenSSH', version: '7.4', distro: null });
    expect(evidenceFromPort('Apache httpd', '2.4.6', '(CentOS)')!.distro).toBe('CentOS');
  });
  it('returns null without a version', () => {
    expect(evidenceFromPort('OpenSSH', null, null)).toBeNull();
  });
});

describe('resolveAlias', () => {
  it('resolves both header and tech label forms', () => {
    for (const n of ['Apache', 'Apache HTTP Server', 'apache httpd']) {
      expect(resolveAlias(n)?.pairs).toContainEqual(['apache', 'http_server']);
    }
    expect(resolveAlias('OpenSSL')?.pairs).toContainEqual(['openssl', 'openssl']);
    expect(resolveAlias('PHP')?.pairs).toContainEqual(['php', 'php']);
    expect(resolveAlias('OpenSSH')?.pairs).toContainEqual(['openbsd', 'openssh']);
  });
  it('rejects products outside the allowlist', () => {
    expect(resolveAlias('jQuery')).toBeNull();
    expect(resolveAlias('Apache Traffic Server')).toBeNull();
    expect(resolveAlias('Apache-Coyote')).toBeNull();
  });
});

describe('matchCves', () => {
  const ev = (name: string, version: string, distro: string | null = null): Evidence =>
    ({ name, version, raw: version, distro });

  it('matches an exact version row', () => {
    const lk = fake([row({ cve_id: 'CVE-2020-0001', version: '2.4.6' }), row({ cve_id: 'CVE-2020-0002', version: '2.4.7' })]);
    const { matches } = matchCves([ev('Apache', '2.4.6')], lk);
    expect(matches.map((m) => m.cve)).toEqual(['CVE-2020-0001']);
    expect(matches[0]).toMatchObject({ rule: 'exact', cvss: 7.5, cvssVersion: '3.1', confidence: 'version-match', cpe: 'cpe:2.3:a:apache:http_server:2.4.6' });
  });
  it('matches version + update_ (OpenSSH 9.3p1)', () => {
    const lk = fake([
      row({ cve_id: 'CVE-2023-0001', vendor: 'openbsd', product: 'openssh', version: '9.3', update_: 'p1' }),
      row({ cve_id: 'CVE-2023-0002', vendor: 'openbsd', product: 'openssh', version: '9.3', update_: 'p2' }),
    ]);
    const { matches } = matchCves([ev('OpenSSH', '9.3p1')], lk);
    expect(matches.map((m) => [m.cve, m.rule])).toEqual([['CVE-2023-0001', 'update']]);
  });
  it('matches a range row, once per CVE', () => {
    const lk = fake([
      row({ cve_id: 'CVE-2021-0001', start_incl: '2.4.0', end_excl: '2.4.10' }),
      row({ cve_id: 'CVE-2021-0001', version: '2.4.6' }),
      row({ cve_id: 'CVE-2021-0002', start_incl: '2.4.7', end_excl: '2.4.10' }),
    ]);
    const { matches } = matchCves([ev('Apache HTTP Server', '2.4.6')], lk);
    expect(matches).toHaveLength(1);
    expect(matches[0]).toMatchObject({ cve: 'CVE-2021-0001', rule: 'exact' });
  });
  it('flags distro banners as version-match-distro', () => {
    const lk = fake([row({ cve_id: 'CVE-2020-0001', version: '2.4.6' })]);
    expect(matchCves([ev('Apache', '2.4.6', 'CentOS')], lk).matches[0]!.confidence).toBe('version-match-distro');
  });
  it('counts evidence with an unusable version as skipped', () => {
    const r = matchCves([ev('Apache', '2')], fake([]));
    expect(r.skipped).toBe(1);
    expect(r.matches).toEqual([]);
  });
  it('ignores non-allowlisted products and CVEs without a CVSS score', () => {
    const lk = fake([row({ cve_id: 'CVE-2020-0003', version: '2.4.6' })], { 'CVE-2020-0003': null });
    expect(matchCves([ev('jQuery', '3.1.0')], lk).matches).toEqual([]);
    expect(matchCves([ev('Apache', '2.4.6')], lk).matches).toEqual([]);
  });
});

describe('severityForCvss', () => {
  it('uses the nmap buckets', () => {
    expect([9, 7, 4, 3.9].map(severityForCvss)).toEqual(['critical', 'high', 'medium', 'low']);
  });
});
