import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { parseWpscanStdout, wpscanCve, wpscanCves, wpscanRows, wpscanSeverity } from '../src/lib/wpscan-parse.js';

const fixture = (name: string): string => fs.readFileSync(path.join(__dirname, 'fixtures/wpscan', name), 'utf8');

describe('parseWpscanStdout', () => {
  it('parses the pretty-printed document of a WordPress target', () => {
    const p = parseWpscanStdout(fixture('wordpress-pretty.json')) as { version: { number: string }; interesting_findings: unknown[] };
    expect(p.version.number).toBe('6.4.2');
    expect(p.interesting_findings).toHaveLength(4);
  });

  it('parses the document of a target that is not WordPress', () => {
    expect(parseWpscanStdout(fixture('not-wordpress-pretty.json'))).toMatchObject({ scan_aborted: expect.any(String) });
  });

  it('skips text before the document', () => {
    expect(parseWpscanStdout('warning: something\n{\n  "a": 1\n}\n')).toEqual({ a: 1 });
  });

  it('throws on output with no JSON object', () => {
    expect(() => parseWpscanStdout('boom\n')).toThrow();
    expect(() => parseWpscanStdout('  \n')).toThrow();
  });
});

describe('wpscanCve', () => {
  it.each([
    [{ references: { cve: ['2014-4663'] } }, 'CVE-2014-4663'],
    [{ references: { cve: '2014-4663' } }, 'CVE-2014-4663'],
    [{ references: { cve: ['CVE-2014-4663'] } }, 'CVE-2014-4663'],
    [{ references: {} }, null],
    [{}, null],
  ])('%j -> %s', (v, want) => { expect(wpscanCve(v)).toBe(want); });
});

describe('wpscanCves', () => {
  it('keeps every id, prefixed and de-duplicated', () => {
    expect(wpscanCves({ references: { cve: ['2024-0001', 'CVE-2024-0002', '2024-0001'] } })).toEqual(['CVE-2024-0001', 'CVE-2024-0002']);
    expect(wpscanCves({ references: { cve: '2024-0003' } })).toEqual(['CVE-2024-0003']);
    expect(wpscanCves({})).toEqual([]);
  });
});

describe('wpscanSeverity', () => {
  it.each([
    [{ score: '10.0' }, 'critical'], [{ score: '9.0' }, 'critical'], [{ score: '8.9' }, 'high'], [{ score: '7.0' }, 'high'],
    [{ score: '6.9' }, 'medium'], [{ score: '4.0' }, 'medium'], [{ score: '3.9' }, 'low'], [{ score: 0.1 }, 'low'],
    [{ score: '0' }, 'high'], [{ score: 'n/a' }, 'high'], [{}, 'high'], [null, 'high'], [undefined, 'high'],
  ])('cvss %j -> %s', (cvss, want) => { expect(wpscanSeverity(cvss)).toBe(want); });
});

describe('wpscanRows', () => {
  const real = (name: string) => parseWpscanStdout(fixture(name));
  const brief = (rows: ReturnType<typeof wpscanRows>) => rows.map((r) => [r.category, r.severity, r.title, r.cve, r.matched_at]);
  const notInteresting = (rows: ReturnType<typeof wpscanRows>) => rows.filter((r) => !['headers', 'robots_txt', 'readme', 'wp_cron', 'interesting'].includes(r.category));

  it('maps the enumeration keys of a real run', () => {
    expect(brief(notInteresting(wpscanRows(real('keys-enumerate-pretty.json'))))).toEqual([
      ['timthumb', 'medium', 'timthumb exposed: http://wp.example/timthumb.php', null, 'http://wp.example/timthumb.php'],
      ['timthumb-vulnerability', 'high', 'http://wp.example/timthumb.php: Timthumb <= 2.8.13 WebShot Remote Code Execution', 'CVE-2014-4663', 'http://wp.example/timthumb.php'],
      ['config-backup', 'high', 'config backup exposed: http://wp.example/wp-config.php~', null, 'http://wp.example/wp-config.php~'],
      ['db-export', 'high', 'db export exposed: http://wp.example/1.sql', null, 'http://wp.example/1.sql'],
      ['wordpress-users', 'info', 'WordPress users (2): admin-example, editor-example', null, null],
    ]);
  });

  it('maps what the wrapper flags alone reveal', () => {
    expect(brief(notInteresting(wpscanRows(real('keys-wrapper-flags-pretty.json'))))).toEqual([
      ['config-backup', 'high', 'config backup exposed: http://wp.example/wp-config.php~', null, 'http://wp.example/wp-config.php~'],
    ]);
  });

  it('stores nothing for keys the target does not have', () => {
    expect(wpscanRows({ config_backups: {}, db_exports: {}, timthumbs: {}, users: {}, main_theme: null, themes: {}, plugins: {} })).toEqual([]);
    expect(wpscanRows({ scan_aborted: 'not wordpress' })).toEqual([]);
  });

  it('lists the users in one row, with no credential-like field', () => {
    const rows = wpscanRows({ users: { zed: { id: 3, found_by: 'x', password: 'p', hash: 'h' }, amy: { id: 1, found_by: 'y' } } });
    expect(rows).toHaveLength(1);
    expect(rows[0]!.title).toBe('WordPress users (2): amy, zed');
    expect(JSON.stringify(rows[0]!.meta)).not.toMatch(/password|hash|"p"|"h"/);
    expect(rows[0]!.meta).toEqual({ users: [{ slug: 'amy', id: 1, found_by: 'y' }, { slug: 'zed', id: 3, found_by: 'x' }] });
  });

  it('treats main_theme and themes vulnerabilities like plugin vulnerabilities, once per theme', () => {
    const v = { title: 'theme xss', cvss: { score: '6.1', vector: 'v' }, references: { cve: ['2024-1111'] } };
    const rows = wpscanRows({
      main_theme: { slug: 'demo-theme', vulnerabilities: [v] },
      themes: { 'demo-theme': { slug: 'demo-theme', vulnerabilities: [v] }, other: { slug: 'other', vulnerabilities: [{ title: 'other bug' }] } },
      plugins: { 'demo-plugin': { vulnerabilities: [{ title: 'plugin bug' }] } },
    });
    expect(brief(rows)).toEqual([
      ['plugin-vulnerability', 'high', 'demo-plugin: plugin bug', null, null],
      ['theme-vulnerability', 'medium', 'demo-theme: theme xss', 'CVE-2024-1111', null],
      ['theme-vulnerability', 'high', 'other: other bug', null, null],
    ]);
  });

  it('sets the severity from the cvss score and keeps the default without one', () => {
    const vulns = [
      { title: 'a', cvss: { score: '9.8' } }, { title: 'b', cvss: { score: '7.5' } }, { title: 'c', cvss: { score: '5.0' } },
      { title: 'd', cvss: { score: '2.0' } }, { title: 'e' },
    ];
    expect(wpscanRows({ version: { vulnerabilities: vulns } }).map((r) => r.severity)).toEqual(['critical', 'high', 'medium', 'low', 'high']);
  });

  it('writes one row per CVE of a vulnerability, each carrying all of them and the numeric score', () => {
    const rows = wpscanRows({ version: { vulnerabilities: [{ title: 'pair', cvss: { score: '8.1', vector: 'vec' }, references: { cve: ['2024-0001', '2024-0002'] } }] } });
    expect(rows.map((r) => [r.title, r.cve])).toEqual([['pair', 'CVE-2024-0001'], ['pair', 'CVE-2024-0002']]);
    for (const r of rows) expect(r.meta).toMatchObject({ cves: ['CVE-2024-0001', 'CVE-2024-0002'], cvss: 8.1, cvss_vector: 'vec' });
  });


  it('keeps two vulnerabilities of one plugin that share a title', () => {
    const rows = wpscanRows({ plugins: { p: { vulnerabilities: [
      { title: 'XSS', references: { cve: ['2020-0001'] } }, { title: 'XSS', references: { cve: ['2021-0002'] } },
    ] } } });
    expect(rows.map((r) => r.cve)).toEqual(['CVE-2020-0001', 'CVE-2021-0002']);
  });

  it('stores a theme vulnerability once when main_theme and themes both list it', () => {
    const v = { title: 'same', references: { cve: ['2024-0001'], wpvulndb: ['111'] } };
    const rows = wpscanRows({ main_theme: { slug: 't', vulnerabilities: [v] }, themes: { t: { slug: 't', vulnerabilities: [v, { title: 'same', references: { wpvulndb: ['222'] } }] } } });
    expect(rows.map((r) => [r.title, r.cve])).toEqual([['t: same', 'CVE-2024-0001'], ['t: same', null]]);
  });



  it('bounds and sanitises the users title and keeps the clean full list in meta', () => {
    const evil = 'evil\nCRITICAL: forged, x';
    const rows = wpscanRows({ users: { [evil]: { id: 1 }, a: { id: 2 } } });
    expect(rows[0]!.title).toBe('WordPress users (2): a, evilCRITICAL: forged x');
    expect(rows[0]!.title).not.toMatch(/[\u0000-\u001f\u007f\u2028\u2029]/);
    expect((rows[0]!.meta as { users: { slug: string }[] }).users.map((u) => u.slug)).toEqual(['a', 'evilCRITICAL: forged, x']);
  });

  it('caps the users title at five slugs of 40 characters, whatever the user count', () => {
    const users = Object.fromEntries(Array.from({ length: 2000 }, (_, i) => [`user${String(i).padStart(4, '0')}${'x'.repeat(60)}`, { id: i }]));
    const rows = wpscanRows({ users });
    expect(rows[0]!.title.length).toBeLessThan(260);
    expect(rows[0]!.title.startsWith('WordPress users (2000): ')).toBe(true);
    expect(rows[0]!.title.endsWith('…')).toBe(true);
    expect((rows[0]!.meta as { users: unknown[] }).users).toHaveLength(2000);
  });

  it('gives the same title for the same set of users in any order', () => {
    const a = wpscanRows({ users: { b: { id: 2 }, a: { id: 1 } } })[0]!.title;
    expect(wpscanRows({ users: { a: { id: 1 }, b: { id: 2 } } })[0]!.title).toBe(a);
  });
});
