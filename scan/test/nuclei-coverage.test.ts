import { describe, it, expect } from 'vitest';
import { rowKey, nucleiCoveredTargets, nucleiSkippedHosts, parseMatched, hostOf, nucleiInputKeys, selfKey, inputKey, targetsWithKeysOutside } from '../src/lib/nuclei-coverage.js';

const T = 'www.example.test';
const ssl = { type: 'ssl', 'matched-at': `${T}:443`, stored: true };
const inputs = nucleiInputKeys([T], [`https://${T}/app/login`]);
const base = { inputs, openKeys: new Map<string, string[]>() };
const http = { type: 'http', 'matched-at': `https://${T}/app/login`, stored: true };
const bareRow = (scheme: string) => ({ type: 'http', 'matched-at': `${scheme}://${T}/`, url: `${scheme}://${T}`, stored: true });

describe('nucleiCoveredTargets', () => {
  it('covers nothing on the host pass', () => {
    expect(nucleiCoveredTargets([T], [ssl, http], { fromUrls: false, exitCode: 0, ...base })).toEqual([]);
  });

  it('covers nothing when nuclei did not exit 0 (error or scan-timeout kill)', () => {
    expect(nucleiCoveredTargets([T], [ssl], { fromUrls: true, exitCode: -1, ...base })).toEqual([]);
    expect(nucleiCoveredTargets([T], [ssl], { fromUrls: true, exitCode: 1, ...base })).toEqual([]);
  });

  it('does not cover a target that only has dns rows', () => {
    const dns = { type: 'dns', 'matched-at': T, stored: true };
    expect(nucleiCoveredTargets([T], [dns], { fromUrls: true, exitCode: 0, ...base })).toEqual([]);
  });

  it('does not cover a target with no row, nor one matched off-target', () => {
    const other = { type: 'http', 'matched-at': 'https://other.example.test/', host: T, stored: true };
    expect(nucleiCoveredTargets([T], [], { fromUrls: true, exitCode: 0, ...base })).toEqual([]);
    expect(nucleiCoveredTargets([T], [other], { fromUrls: true, exitCode: 0, ...base })).toEqual([]);
    expect(nucleiCoveredTargets([T], [{ type: 'http', 'matched-at': `https://evil.example.test/${T}`, stored: true }], { fromUrls: true, exitCode: 0, ...base })).toEqual([]);
  });

  it('covers a target through an ssl row on host:443', () => {
    expect(nucleiCoveredTargets([T], [ssl], { fromUrls: true, exitCode: 0, ...base })).toEqual([T]);
  });

  it('covers a target through a URL-sample row', () => {
    expect(nucleiCoveredTargets([T], [http], { fromUrls: true, exitCode: 0, ...base })).toEqual([T]);
  });

  it('compares hostnames case-insensitively and ignores the port', () => {
    const r = { type: 'http', 'matched-at': 'https://WWW.Example.test:8443/x', stored: true };
    expect(nucleiCoveredTargets([T], [r], { fromUrls: true, exitCode: 0, ...base })).toEqual([T]);
  });

  it('returns each covered target once, in target order', () => {
    const rows = [http, { type: 'ssl', 'matched-at': 'a.example.test:443', stored: true }];
    expect(nucleiCoveredTargets([T, 'a.example.test', T, 'b.example.test'], rows, { fromUrls: true, exitCode: 0, ...base }))
      .toEqual([T, 'a.example.test']);
  });
});

describe('nucleiCoveredTargets storage and skips', () => {
  const opts = { fromUrls: true, exitCode: 0, ...base };

  it('does not cover a target whose only qualifying row failed to store', () => {
    expect(nucleiCoveredTargets([T], [{ ...ssl, stored: false }], opts)).toEqual([]);
  });

  it('does not cover a target when any of its rows failed to store', () => {
    expect(nucleiCoveredTargets([T], [ssl, { ...http, stored: false }], opts)).toEqual([]);
    expect(nucleiCoveredTargets([T], [ssl, { type: 'dns', 'matched-at': T, stored: false }], opts)).toEqual([]);
  });

  it('does not cover a target whose off-host match (keyed on row.host) failed to store', () => {
    const off = { type: 'http', 'matched-at': 'https://sso.example.test/login', host: T, stored: false };
    expect(nucleiCoveredTargets([T], [ssl, off], opts)).toEqual([]);
  });

  it('does not cover a target nuclei skipped, even with rows', () => {
    expect(nucleiCoveredTargets([T], [ssl], { ...opts, skipped: new Set([T]) })).toEqual([]);
  });
});

describe('nucleiSkippedHosts', () => {
  const skipLine = '[INF] Skipped www.example.test:443 from target list as found unresponsive 30 times';
  const errLine = (addr: string) => JSON.stringify({ template: 't.yaml', type: 'http', input: `https://${addr}/p`, address: addr, error: 'cause="connection reset by peer"', kind: 'unknown-error' });

  it('reads the skip message from stderr, port and case ignored', () => {
    const got = nucleiSkippedHosts(`noise\n${skipLine}\n[INF] Skipped WWW2.Example.test from target list as found unresponsive 2 times\n`, [], 30);
    expect([...got].sort()).toEqual(['www.example.test', 'www2.example.test']);
  });

  it('counts elog errors per host against the limit', () => {
    const lines = [...Array(3).fill(errLine('a.example.test:443')), errLine('b.example.test:443'), 'not json'];
    expect([...nucleiSkippedHosts('', lines, 3)]).toEqual(['a.example.test']);
  });

  it('is empty when nothing was skipped', () => {
    expect(nucleiSkippedHosts('[INF] Scan completed', [], 30).size).toBe(0);
  });
});

describe('parseMatched', () => {
  it('returns host and hostname from one parse', () => {
    expect(parseMatched('https://WWW.Example.test:8443/x')).toEqual({ host: 'www.example.test:8443', hostname: 'www.example.test' });
    expect(parseMatched('www.example.test:443')).toEqual({ host: 'www.example.test', hostname: 'www.example.test' });
    expect(parseMatched(undefined)).toEqual({ host: '', hostname: '' });
  });
});

describe('hostOf', () => {
  it('extracts the host of a URL or host:port', () => {
    expect(hostOf('https://www.example.test/a')).toBe('www.example.test');
    expect(hostOf(undefined)).toBe('');
  });
});

describe('open findings outside this run\'s inputs', () => {
  const opts = { fromUrls: true, exitCode: 0, inputs };
  const open = (...keys: string[]) => new Map([[T, keys.map(inputKey)]]);

  it('does not cover a target with an open key the run never fed to nuclei', () => {
    expect(nucleiCoveredTargets([T], [http], { ...opts, openKeys: open(`https://${T}/app/other`) })).toEqual([]);
  });

  it('does not cover a target with an open key on another origin', () => {
    expect(nucleiCoveredTargets([T], [http], { ...opts, openKeys: open(`http://${T}/app/login`) })).toEqual([]);
    expect(nucleiCoveredTargets([T], [http], { ...opts, openKeys: open(`https://${T}:8443/app/login`) })).toEqual([]);
  });

  it('covers a target whose open keys are all inputs, however the url is written', () => {
    const keys = open(`https://${T}/app/login`, `https://${T.toUpperCase()}/app/login/`, `https://${T}`, `${T}:443`);
    expect(nucleiCoveredTargets([T], [http, bareRow('https')], { ...opts, openKeys: keys })).toEqual([T]);
  });

  it('scopes a bare host to the scheme nuclei used on it', () => {
    expect(nucleiCoveredTargets([T], [http, bareRow('http')], { ...opts, openKeys: open(`https://${T}`) })).toEqual([]);
    expect(nucleiCoveredTargets([T], [http, bareRow('https')], { ...opts, openKeys: open(`http://${T}`) })).toEqual([]);
    expect(nucleiCoveredTargets([T], [http, bareRow('http')], { ...opts, openKeys: open(`http://${T}`) })).toEqual([T]);
  });

  it('adds no root key for a bare host with no row of its own', () => {
    expect(nucleiCoveredTargets([T], [http], { ...opts, openKeys: open(`https://${T}`) })).toEqual([]);
    expect(nucleiCoveredTargets([T], [http], { ...opts, openKeys: open(`http://${T}`) })).toEqual([]);
  });

  it('reads the scheme field when a row url has none', () => {
    const row = { type: 'http', 'matched-at': `http://${T}/`, url: T, scheme: 'http', stored: true };
    expect(nucleiCoveredTargets([T], [http, row], { ...opts, openKeys: open(`http://${T}`) })).toEqual([T]);
    expect(nucleiCoveredTargets([T], [http, row], { ...opts, openKeys: open(`https://${T}`) })).toEqual([]);
  });

  const js = { type: 'javascript', 'matched-at': T, host: T, url: T, stored: true };
  const tcp = (url: string) => ({ type: 'tcp', 'matched-at': url, host: T, url, scheme: undefined, stored: true });

  it('adds no root key from a row whose url and scheme field name no scheme', () => {
    expect(nucleiCoveredTargets([T], [bareRow('http'), js], { ...opts, openKeys: open(`https://${T}`) })).toEqual([]);
    expect(nucleiCoveredTargets([T], [bareRow('http'), tcp(`${T}:443`)], { ...opts, openKeys: open(`https://${T}`) })).toEqual([]);
  });

  it('keys a non-http row by its authority, from the url or else matched-at', () => {
    expect(rowKey(T, { type: 'tcp', url: `${T}:22`, matchedAt: null })).toBe(`self:${T}:22`);
    expect(rowKey(T, { type: 'ssl', url: null, matchedAt: `${T}:8443` })).toBe(`ssl:${T}:8443`);
    expect(rowKey(T, { type: 'ssl', url: null, matchedAt: T })).toBe(`ssl:${T}:443`);
    expect(rowKey(T, { type: 'javascript', url: T, matchedAt: T })).toBe(`self:${T}`);
    expect(rowKey(T, { type: 'dns', url: null, matchedAt: `ns.${T}` })).toBe(`self:${T}`);
    expect(rowKey(T, { type: 'http', url: `https://${T}/a`, matchedAt: null })).toBe(`https://${T}/a`);
  });

  it('examines an ssl authority only through an input, never through a stored row', () => {
    const ssl8443 = new Map([[T, [rowKey(T, { type: 'ssl', url: null, matchedAt: `${T}:8443` })]]]);
    expect(nucleiCoveredTargets([T], [http], { ...opts, openKeys: ssl8443 })).toEqual([]);
    const sample = nucleiInputKeys([T], [`https://${T}:8443/app`]);
    expect(nucleiCoveredTargets([T], [http], { ...opts, inputs: sample, openKeys: ssl8443 })).toEqual([T]);
    const sslRow = { type: 'ssl', 'matched-at': `${T}:8443`, stored: true };
    expect(nucleiCoveredTargets([T], [http, sslRow], { ...opts, openKeys: ssl8443 })).toEqual([]);
    expect(nucleiCoveredTargets([T], [http, tcp(`${T}:8443`)], { ...opts, openKeys: ssl8443 })).toEqual([]);
  });

  it('examines t:443 ssl for a bare target input', () => {
    const open443 = new Map([[T, [rowKey(T, { type: 'ssl', url: null, matchedAt: `${T}:443` })]]]);
    expect(nucleiCoveredTargets([T], [http], { ...opts, inputs: nucleiInputKeys([T], []), openKeys: open443 })).toEqual([T]);
  });

  it('covers a tcp finding on :22 only when this run stored a row on :22', () => {
    const open22 = new Map([[T, [rowKey(T, { type: 'tcp', url: `${T}:22`, matchedAt: null })]]]);
    expect(nucleiCoveredTargets([T], [http], { ...opts, openKeys: open22 })).toEqual([]);
    expect(nucleiCoveredTargets([T], [http, tcp(`${T}:22`)], { ...opts, openKeys: open22 })).toEqual([T]);
    expect(nucleiCoveredTargets([T], [http, tcp(`${T}:2222`)], { ...opts, openKeys: open22 })).toEqual([]);
  });

  it('counts an open row with no url as inside when the bare target was an input', () => {
    expect(nucleiCoveredTargets([T], [http], { ...opts, openKeys: new Map([[T, [selfKey(T)]]]) })).toEqual([T]);
  });

  it('counts an open row with no url as outside when the target was not an input', () => {
    const other = nucleiInputKeys([], [`https://${T}/app/login`]);
    expect(nucleiCoveredTargets([T], [http], { fromUrls: true, exitCode: 0, inputs: other, openKeys: new Map([[T, [selfKey(T)]]]) })).toEqual([]);
  });

  it('treats an open row with no key as outside', () => {
    expect(nucleiCoveredTargets([T], [http], { ...opts, openKeys: open('') })).toEqual([]);
  });

  it('covers nothing when the open findings could not be read', () => {
    expect(nucleiCoveredTargets([T], [http], { ...opts, openKeys: null })).toEqual([]);
  });

  it('lists the targets that have a key outside the inputs', () => {
    const m = new Map([[T, [`https://${T}/gone`]], ['b.example.test', [`https://b.example.test`]]]);
    expect(targetsWithKeysOutside(m, nucleiInputKeys([T, 'b.example.test'], ['https://b.example.test']))).toEqual([T]);
  });

  it('keys an input url by scheme, host, port and path only', () => {
    expect(inputKey(`HTTPS://WWW.Example.test:443/a/b/?q=1`)).toBe(`https://www.example.test/a/b?q=1`);
    expect(inputKey('www.example.test:8443')).toBe('https://www.example.test:8443');
  });
});
