import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { syncMmdb } from '../src/lib/mmdb.js';

const MIB = 1024 * 1024;

let dir: string;
let file: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mmdb-test-'));
  file = path.join(dir, 'ipinfo_lite.mmdb');
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

const body = (n: number) => new Response(Buffer.alloc(n, 1));
const ok = async () => {};
const noTmp = () =>
  expect(fs.readdirSync(dir).filter((n) => n !== path.basename(file))).toEqual([]);

const slowBody = (fill: number, total: number, errorAfter?: number) => {
  const chunk = 256 * 1024;
  let sent = 0;
  const stream = new ReadableStream<Uint8Array>({
    async pull(c) {
      await new Promise((r) => setTimeout(r, 5));
      if (errorAfter !== undefined && sent >= errorAfter) {
        c.error(new Error('connection reset'));
        return;
      }
      c.enqueue(new Uint8Array(chunk).fill(fill));
      sent += chunk;
      if (sent >= total) c.close();
    },
  });
  return new Response(stream);
};

describe('syncMmdb', () => {
  it('keeps the old file on an HTTP error', async () => {
    fs.writeFileSync(file, 'old');
    const r = await syncMmdb({
      file,
      fetchFn: async () => new Response('nope', { status: 503 }),
      validate: ok,
    });
    expect(r.ok).toBe(false);
    expect(fs.readFileSync(file, 'utf8')).toBe('old');
    noTmp();
  });

  it('keeps the old file when the fetch throws', async () => {
    fs.writeFileSync(file, 'old');
    const r = await syncMmdb({
      file,
      fetchFn: async () => {
        throw new Error('network down');
      },
      validate: ok,
    });
    expect(r.ok).toBe(false);
    expect(fs.readFileSync(file, 'utf8')).toBe('old');
    noTmp();
  });

  it('keeps the old file when the body is under 1 MiB', async () => {
    fs.writeFileSync(file, 'old');
    const r = await syncMmdb({
      file,
      fetchFn: async () => body(MIB - 1),
      validate: ok,
    });
    expect(r.ok).toBe(false);
    expect(fs.readFileSync(file, 'utf8')).toBe('old');
    noTmp();
  });

  it('keeps the old file when validation fails', async () => {
    fs.writeFileSync(file, 'old');
    const r = await syncMmdb({
      file,
      fetchFn: async () => body(MIB),
      validate: async () => {
        throw new Error('not an mmdb');
      },
    });
    expect(r.ok).toBe(false);
    expect(fs.readFileSync(file, 'utf8')).toBe('old');
    noTmp();
  });

  it('replaces the file on success and leaves no .tmp', async () => {
    fs.writeFileSync(file, 'old');
    const seen: string[] = [];
    const r = await syncMmdb({
      file,
      fetchFn: async () => body(MIB),
      validate: async (p) => {
        seen.push(p);
      },
    });
    expect(r.ok).toBe(true);
    expect(fs.statSync(file).size).toBe(MIB);
    expect(seen).toHaveLength(1);
    const tmpPath = seen[0] as string;
    expect(path.dirname(tmpPath)).toBe(dir);
    expect(tmpPath).not.toBe(file);
    expect(tmpPath.endsWith('.tmp')).toBe(true);
    noTmp();
  });

  it('creates the file when there was none', async () => {
    const r = await syncMmdb({
      file,
      fetchFn: async () => body(2 * MIB),
      validate: ok,
    });
    expect(r.ok).toBe(true);
    expect(fs.statSync(file).size).toBe(2 * MIB);
    noTmp();
  });

  it('rejects a garbage body with the default validator and keeps the old file', async () => {
    fs.writeFileSync(file, 'old');
    const r = await syncMmdb({ file, fetchFn: async () => body(2 * MIB) });
    expect(r.ok).toBe(false);
    expect(fs.readFileSync(file, 'utf8')).toBe('old');
    noTmp();
  });

  it('keeps the old file when the body stream errors mid-download', async () => {
    fs.writeFileSync(file, 'old');
    const r = await syncMmdb({
      file,
      fetchFn: async () => slowBody(1, 4 * MIB, MIB),
      validate: ok,
    });
    expect(r.ok).toBe(false);
    expect(fs.readFileSync(file, 'utf8')).toBe('old');
    noTmp();
  });

  it('gives concurrent runs their own temp file', async () => {
    const [a, b] = await Promise.all([
      syncMmdb({ file, fetchFn: async () => slowBody(1, 2 * MIB), validate: ok }),
      syncMmdb({ file, fetchFn: async () => slowBody(2, 3 * MIB), validate: ok }),
    ]);
    expect(a.ok).toBe(true);
    expect(b.ok).toBe(true);
    const got = fs.readFileSync(file);
    const isBody = (fill: number, n: number) => got.length === n && got.every((x) => x === fill);
    expect(isBody(1, 2 * MIB) || isBody(2, 3 * MIB)).toBe(true);
    noTmp();
  });
});
