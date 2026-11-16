import { describe, it, expect, afterEach } from 'vitest';
import dgram from 'node:dgram';
import dns from 'node:dns';
import { sanitizePtrNames, lookupPtrs, arpaName, ptrOutcome } from '../src/lib/ptr.js';

const err = (code: string): Error => Object.assign(new Error(code), { code });

describe('sanitizePtrNames', () => {
  it('lowercases, strips one trailing dot and keeps order', () => {
    expect(sanitizePtrNames(['Host-1.Example.NET.', 'b.example'])).toEqual(['host-1.example.net', 'b.example']);
  });
  it('strips only one trailing dot', () => {
    expect(sanitizePtrNames(['a.example..'])).toEqual([]);
  });
  it('drops invalid labels', () => {
    expect(sanitizePtrNames(['-a.example', 'a-.example', 'a..example', '.example', '', 'a b.example', 'a_b.example', 'ü.example'])).toEqual([]);
  });
  it('drops overlong labels and names', () => {
    const l63 = 'a'.repeat(63);
    expect(sanitizePtrNames([`${l63}.example`])).toEqual([`${l63}.example`]);
    expect(sanitizePtrNames([`${'a'.repeat(64)}.example`])).toEqual([]);
    const long = Array(5).fill('a'.repeat(50)).join('.');
    expect(long.length).toBeGreaterThan(253);
    expect(sanitizePtrNames([long])).toEqual([]);
    const ok = [...Array(3).fill('a'.repeat(63)), 'b'.repeat(61)].join('.');
    expect(ok.length).toBe(253);
    expect(sanitizePtrNames([ok])).toEqual([ok]);
  });
  it('drops control characters and markup', () => {
    expect(sanitizePtrNames(['a\u0000b.example', 'a\n.example', '<script>alert(1)</script>', 'x.example"><img', 'ok.example'])).toEqual(['ok.example']);
  });
  it('dedupes after normalising and caps at 5', () => {
    expect(sanitizePtrNames(['A.example', 'a.example.', 'a.example'])).toEqual(['a.example']);
    const many = Array.from({ length: 8 }, (_, i) => `h${i}.example`);
    expect(sanitizePtrNames(many)).toEqual(many.slice(0, 5));
  });
  it('returns [] for non-array and non-string members', () => {
    expect(sanitizePtrNames(undefined)).toEqual([]);
    expect(sanitizePtrNames(null)).toEqual([]);
    expect(sanitizePtrNames('a.example')).toEqual([]);
    expect(sanitizePtrNames({ length: 1, 0: 'a.example' })).toEqual([]);
    expect(sanitizePtrNames([1, null, {}, ['a.example'], 'ok.example'])).toEqual(['ok.example']);
  });
});

describe('lookupPtrs', () => {
  it('maps resolver names through sanitising and a failure to null', async () => {
    const m = await lookupPtrs(['192.0.2.1', '192.0.2.2'], {
      budgetMs: 10_000,
      resolver: { resolvePtr: async (n) => { if (n.startsWith('1.')) return ['H.Example.']; throw err('ESERVFAIL'); } },
    });
    expect([...m.entries()]).toEqual([['192.0.2.1', ['h.example']], ['192.0.2.2', null]]);
  });

  it('queries the arpa name, not the address', async () => {
    const seen: string[] = [];
    await lookupPtrs(['192.0.2.1', '2001:db8::1'], { budgetMs: 10_000, resolver: { resolvePtr: async (n) => { seen.push(n); return []; } } });
    expect(seen).toEqual(['1.2.0.192.in-addr.arpa', `1.${'0.'.repeat(23)}8.b.d.0.1.0.0.2.ip6.arpa`]);
  });

  it('maps a synchronous throw and a non-promise failure to null', async () => {
    const m = await lookupPtrs(['192.0.2.1', '192.0.2.2'], {
      budgetMs: 10_000,
      resolver: { resolvePtr: (n) => { if (n.startsWith('1.')) throw new Error('sync'); return Promise.reject('plain'); } },
    });
    expect([...m.values()]).toEqual([null, null]);
  });

  it('sanitises resolver output; all-invalid names give []', async () => {
    const m = await lookupPtrs(['192.0.2.1'], { budgetMs: 10_000, resolver: { resolvePtr: async () => ['<b>x</b>'] } });
    expect(m.get('192.0.2.1')).toEqual([]);
  });

  it('times a hanging lookup out to null and clears its timer', async () => {
    let cancelled = 0;
    const t0 = Date.now();
    const m = await lookupPtrs(['192.0.2.1'], {
      timeoutMs: 50, budgetMs: 10_000,
      resolver: { resolvePtr: () => new Promise<string[]>(() => {}), cancel: () => { cancelled++; } },
    });
    expect(m.get('192.0.2.1')).toBeNull();
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(cancelled).toBe(1);
  });

  it('never exceeds the concurrency cap', async () => {
    let inflight = 0, peak = 0;
    const ips = Array.from({ length: 12 }, (_, i) => `192.0.2.${i + 1}`);
    const m = await lookupPtrs(ips, {
      concurrency: 3, budgetMs: 10_000,
      resolver: { resolvePtr: async () => { inflight++; peak = Math.max(peak, inflight); await new Promise((r) => setTimeout(r, 5)); inflight--; return ['a.example']; } },
    });
    expect(peak).toBe(3);
    expect(m.size).toBe(12);
    expect([...m.values()].every((v) => v?.[0] === 'a.example')).toBe(true);
  });

  it('starts nothing new once the budget is spent and maps the rest to null', async () => {
    let clock = 0;
    const started: string[] = [];
    const ips = ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4'];
    const stats = { skippedByBudget: -1 };
    const m = await lookupPtrs(ips, {
      concurrency: 1, budgetMs: 100, now: () => clock, stats,
      resolver: { resolvePtr: async (ip) => { started.push(ip); clock += 60; return ['a.example']; } },
    });
    expect(started).toEqual(['1.2.0.192.in-addr.arpa', '2.2.0.192.in-addr.arpa']);
    expect(m.get('192.0.2.1')).toEqual(['a.example']);
    expect(m.get('192.0.2.2')).toEqual(['a.example']);
    expect(m.get('192.0.2.3')).toBeNull();
    expect(m.get('192.0.2.4')).toBeNull();
    expect(m.size).toBe(4);
    expect(stats.skippedByBudget).toBe(2);
  });

  it('looks duplicates up once', async () => {
    const seen: string[] = [];
    const m = await lookupPtrs(['192.0.2.1', '192.0.2.1', '192.0.2.2'], {
      budgetMs: 10_000, resolver: { resolvePtr: async (ip) => { seen.push(ip); return []; } },
    });
    expect(seen.sort()).toEqual(['1.2.0.192.in-addr.arpa', '2.2.0.192.in-addr.arpa']);
    expect(m.size).toBe(2);
  });

  it('handles an empty list without building a resolver', async () => {
    expect((await lookupPtrs([], { budgetMs: 1 })).size).toBe(0);
  });
});

describe('arpaName', () => {
  it('reverses IPv4 octets', () => {
    expect(arpaName('192.0.2.1')).toBe('1.2.0.192.in-addr.arpa');
  });
  it('expands IPv6 to 32 reversed nibbles', () => {
    expect(arpaName('2001:db8::1')).toBe('1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa');
    expect(arpaName('::')).toBe(`${'0.'.repeat(32)}ip6.arpa`);
    expect(arpaName('::1')).toBe(`1.${'0.'.repeat(31)}ip6.arpa`);
    expect(arpaName('1::')).toBe(`${'0.'.repeat(28)}1.0.0.0.ip6.arpa`);
    expect(arpaName('2001:db8:0:1:0:0:0:2')).toBe('2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa');
  });
  it('expands what normalizeIp emits for IPv4-compatible forms (hex groups)', () => {
    expect(arpaName('::102:304')).toBe(`4.0.3.0.2.0.1.0.${'0.'.repeat(24)}ip6.arpa`);
  });
});

describe('ptrOutcome', () => {
  it('maps only ENOTFOUND and ENODATA to []', () => {
    expect(ptrOutcome(err('ENOTFOUND'))).toEqual([]);
    expect(ptrOutcome(err('ENODATA'))).toEqual([]);
  });
  it('maps every other failure to null', () => {
    for (const c of ['ESERVFAIL', 'EREFUSED', 'EBADRESP', 'ETIMEOUT', 'ECONNREFUSED', 'ECANCELLED']) expect(ptrOutcome(err(c))).toBeNull();
    expect(ptrOutcome(new Error('no code'))).toBeNull();
    expect(ptrOutcome('plain')).toBeNull();
    expect(ptrOutcome(undefined)).toBeNull();
    expect(ptrOutcome(null)).toBeNull();
  });
});

type Mode = 'nx' | 'nodata' | 'ok' | 'hostile' | 'servfail' | 'refused' | 'garbage' | 'silent';
const RCODE: Record<string, number> = { nx: 3, nodata: 0, servfail: 2, refused: 5 };

function dnsReply(msg: Buffer, rcode: number, answers: string[] = []): Buffer {
  let o = 12;
  while (msg[o] !== 0) o += msg[o]! + 1;
  o += 5;
  const h = Buffer.alloc(12);
  msg.copy(h, 0, 0, 2);
  h[2] = 0x81; h[3] = 0x80 | rcode;
  h.writeUInt16BE(1, 4); h.writeUInt16BE(answers.length, 6);
  const parts = [h, msg.subarray(12, o)];
  for (const name of answers) {
    const labels = name.split('.').filter(Boolean).map((l) => { const b = Buffer.from(l, 'latin1'); return Buffer.concat([Buffer.from([b.length]), b]); });
    const rdata = Buffer.concat([...labels, Buffer.from([0])]);
    const rr = Buffer.alloc(12);
    rr.writeUInt16BE(0xc00c, 0); rr.writeUInt16BE(12, 2); rr.writeUInt16BE(1, 4); rr.writeUInt32BE(60, 6); rr.writeUInt16BE(rdata.length, 10);
    parts.push(rr, rdata);
  }
  return Buffer.concat(parts);
}

describe('lookupPtrs against a fake UDP DNS server', () => {
  const sockets: dgram.Socket[] = [];
  const resolvers: dns.promises.Resolver[] = [];
  afterEach(() => {
    for (const r of resolvers.splice(0)) r.cancel();
    for (const s of sockets.splice(0)) s.close();
  });

  const bind = async (): Promise<dgram.Socket> => {
    const s = dgram.createSocket('udp4');
    sockets.push(s);
    await new Promise<void>((res) => s.bind(0, '127.0.0.1', res));
    return s;
  };
  const serve = async (mode: Mode): Promise<string> => {
    const s = await bind();
    s.on('message', (m, r) => {
      let out: Buffer;
      if (mode === 'silent') return;
      if (mode === 'ok') out = dnsReply(m, 0, ['Host.Example.com']);
      else if (mode === 'hostile') out = dnsReply(m, 0, ['<script>x', 'A.B.']);
      else if (mode === 'garbage') out = Buffer.from([m[0]!, m[1]!, 0x81]);
      else out = dnsReply(m, RCODE[mode]!);
      s.send(out, r.port, r.address);
    });
    return `127.0.0.1:${s.address().port}`;
  };
  const closedPort = async (): Promise<string> => {
    const s = await bind();
    const port = s.address().port;
    sockets.splice(sockets.indexOf(s), 1);
    await new Promise<void>((res) => s.close(() => res()));
    return `127.0.0.1:${port}`;
  };
  const ptr = async (server: string, ip = '192.0.2.1'): Promise<string[] | null> => {
    const resolver = new dns.promises.Resolver({ timeout: 400, tries: 1 });
    resolver.setServers([server]);
    resolvers.push(resolver);
    return (await lookupPtrs([ip], { timeoutMs: 400, budgetMs: 10_000, resolver })).get(ip) ?? null;
  };

  it('maps NXDOMAIN and NOERROR-without-answer to []', async () => {
    expect(await ptr(await serve('nx'))).toEqual([]);
    expect(await ptr(await serve('nodata'))).toEqual([]);
  });
  it('returns a sanitised PTR name for v4 and v6', async () => {
    const s = await serve('ok');
    expect(await ptr(s)).toEqual(['host.example.com']);
    expect(await ptr(s, '2001:db8::1')).toEqual(['host.example.com']);
  });
  it('drops hostile names from an answer', async () => {
    expect(await ptr(await serve('hostile'))).toEqual(['a.b']);
  });
  it('maps SERVFAIL, REFUSED and a garbage reply to null', async () => {
    expect(await ptr(await serve('servfail'))).toBeNull();
    expect(await ptr(await serve('refused'))).toBeNull();
    expect(await ptr(await serve('garbage'))).toBeNull();
  });
  it('maps a silent server to null within the timeout', async () => {
    const t0 = Date.now();
    expect(await ptr(await serve('silent'))).toBeNull();
    expect(Date.now() - t0).toBeLessThan(2000);
  });
  it('maps a closed port to null', async () => {
    expect(await ptr(await closedPort())).toBeNull();
  });
});
