import { describe, it, expect, vi } from 'vitest';
import { openDb, type Db } from '../src/lib/db.js';
import { runBannerRecheck } from '../src/banner-recheck.js';
import { runSynthesizeEol } from '../src/synthesize-eol.js';

const NOW = '2026-11-04T00:00:00.000Z';
const T = 'storage.example';

function seed(db: Db, target: string, web_server: string | null, url = `https://${target}`): void {
  db.insertHttpProbe({ target, url, status_code: 301, web_server }, '2026-11-03T00:00:00Z', null);
}

type FetchFn = (url: string, init: RequestInit) => Promise<Response>;
const reply = (status: number, server?: string): Response =>
  new Response(null, { status, headers: server ? { server } : {} });

const rows = (db: Db) =>
  db.raw.prepare('SELECT target, url, status_code, web_server, title FROM http_probes ORDER BY id').all() as
    { target: string; url: string; status_code: number | null; web_server: string | null; title: string | null }[];

describe('runBannerRecheck', () => {
  it('probes a null-banner target and inserts a row with the recovered banner', async () => {
    const db = openDb(':memory:');
    seed(db, T, null);
    const fetchFn = vi.fn<FetchFn>().mockResolvedValue(reply(400, 'MinIO'));
    const res = await runBannerRecheck(db, [T], NOW, null, { fetchFn });
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(fetchFn.mock.calls[0]![0]).toBe(`https://${T}`);
    expect(res.recovered).toBe(1);
    const added = rows(db).filter((r) => r.web_server);
    expect(added).toEqual([{ target: T, url: `https://${T}`, status_code: 400, web_server: 'MinIO', title: null }]);
  });

  it('skips a target that already has a non-null web_server row', async () => {
    const db = openDb(':memory:');
    seed(db, T, null);
    seed(db, T, 'nginx', `http://${T}`);
    const fetchFn = vi.fn<FetchFn>().mockResolvedValue(reply(200, 'MinIO'));
    await runBannerRecheck(db, [T], NOW, null, { fetchFn });
    expect(fetchFn).not.toHaveBeenCalled();
    expect(rows(db)).toHaveLength(2);
  });

  it('inserts nothing when the probe returns no Server header', async () => {
    const db = openDb(':memory:');
    seed(db, T, null);
    const fetchFn = vi.fn<FetchFn>().mockResolvedValue(reply(301));
    const res = await runBannerRecheck(db, [T], NOW, null, { fetchFn });
    expect(res.recovered).toBe(0);
    expect(rows(db)).toHaveLength(1);
  });

  it('inserts nothing when the probe throws', async () => {
    const db = openDb(':memory:');
    seed(db, T, null);
    const fetchFn = vi.fn<FetchFn>().mockRejectedValue(new Error('boom'));
    await runBannerRecheck(db, [T], NOW, null, { fetchFn });
    expect(rows(db)).toHaveLength(1);
  });

  it('falls back to GET when HEAD yields no Server header', async () => {
    const db = openDb(':memory:');
    seed(db, T, null);
    const fetchFn = vi.fn<FetchFn>()
      .mockResolvedValueOnce(reply(400))
      .mockResolvedValueOnce(reply(403, 'MinIO'));
    await runBannerRecheck(db, [T], NOW, null, { fetchFn });
    expect(fetchFn.mock.calls.map((c) => c[1].method)).toEqual(['HEAD', 'GET']);
    expect(rows(db).filter((r) => r.web_server)).toEqual([
      { target: T, url: `https://${T}`, status_code: 403, web_server: 'MinIO', title: null },
    ]);
  });

  it('sends a minimal request: HEAD, redirect manual, abort signal, no browser headers', async () => {
    const db = openDb(':memory:');
    seed(db, T, null);
    const fetchFn = vi.fn<FetchFn>().mockResolvedValue(reply(400, 'MinIO'));
    await runBannerRecheck(db, [T], NOW, null, { fetchFn });
    const init = fetchFn.mock.calls[0]![1];
    expect(init.method).toBe('HEAD');
    expect(init.redirect).toBe('manual');
    expect(init.signal).toBeInstanceOf(AbortSignal);
    const h = Object.fromEntries(Object.entries((init.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v]));
    expect(h['accept']).toBeUndefined();
    expect(h['accept-language']).toBeUndefined();
    expect(h['accept-encoding']).toBeUndefined();
    expect(String(h['user-agent'] ?? '')).not.toMatch(/mozilla|chrome|safari/i);
  });

  it('prefers https and probes one url per target', async () => {
    const db = openDb(':memory:');
    seed(db, T, null, `http://${T}`);
    seed(db, T, null, `https://${T}`);
    const fetchFn = vi.fn<FetchFn>().mockResolvedValue(reply(400, 'MinIO'));
    await runBannerRecheck(db, [T], NOW, null, { fetchFn });
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(fetchFn.mock.calls[0]![0]).toBe(`https://${T}`);
  });

  it('is idempotent: a second run selects and inserts nothing', async () => {
    const db = openDb(':memory:');
    seed(db, T, null);
    const fetchFn = vi.fn<FetchFn>().mockResolvedValue(reply(400, 'MinIO'));
    await runBannerRecheck(db, [T], NOW, null, { fetchFn });
    const n = rows(db).length;
    fetchFn.mockClear();
    await runBannerRecheck(db, [T], NOW, null, { fetchFn });
    expect(fetchFn).not.toHaveBeenCalled();
    expect(rows(db)).toHaveLength(n);
  });

  it('only considers targets in the batch', async () => {
    const db = openDb(':memory:');
    seed(db, T, null);
    seed(db, 'other.example', null);
    const fetchFn = vi.fn<FetchFn>().mockResolvedValue(reply(400, 'MinIO'));
    await runBannerRecheck(db, [T], NOW, null, { fetchFn });
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('feeds the classifier: recheck then synthesize-eol yields exactly one eol-minio high finding', async () => {
    const db = openDb(':memory:');
    seed(db, T, null);
    const fetchFn = vi.fn<FetchFn>().mockResolvedValue(reply(400, 'MinIO'));
    await runBannerRecheck(db, [T], NOW, null, { fetchFn });
    runSynthesizeEol(db, NOW);
    const f = db.raw.prepare("SELECT target, category, severity FROM findings WHERE tool='synthesize-eol'").all();
    expect(f).toEqual([{ target: T, category: 'eol-minio', severity: 'high' }]);
  });
});
