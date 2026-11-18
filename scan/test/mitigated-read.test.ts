import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { probeUrl, fetchCanary } from '../src/lib/catchall.js';
import { probe } from '../src/content-sigs.js';

let server: http.Server;
let base = '';

beforeAll(async () => {
  server = http.createServer((req, res) => {
    if (req.url?.startsWith('/challenge')) {
      res.writeHead(403, { 'cf-mitigated': 'challenge' });
    } else {
      res.writeHead(404);
    }
    res.end();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

const SIG = (path: string) => ({ path, sev: 'info' as const, desc: 'x', match: () => false });

describe('cf-mitigated read from a real response', () => {
  it('probeUrl flags a cf-mitigated 403 and not a plain 404', async () => {
    expect(await probeUrl(`${base}/challenge`, 5)).toMatchObject({ status: 403, mitigated: true });
    expect(await probeUrl(`${base}/plain`, 5)).toMatchObject({ status: 404, mitigated: false });
  });

  it('fetchCanary passes the flag through', async () => {
    // The canary path is random, so serve the challenge from a seed prefix.
    expect(await fetchCanary(`${base}/challenge`, 5)).toMatchObject({ status: 403, mitigated: true });
    expect(await fetchCanary(`${base}/plain`, 5)).toMatchObject({ status: 404, mitigated: false });
  });

  it('content-sigs probe flags a cf-mitigated 403 and not a plain 404', async () => {
    expect(await probe(base, SIG('challenge'), 5000, 1024)).toMatchObject({ status: 403, mitigated: true });
    expect(await probe(base, SIG('plain'), 5000, 1024)).toMatchObject({ status: 404, mitigated: false });
  });
});
