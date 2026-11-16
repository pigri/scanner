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
const noTmp = () => expect(fs.existsSync(`${file}.tmp`)).toBe(false);

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
    expect(seen).toEqual([`${file}.tmp`]);
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
});
