import crypto from 'node:crypto';
import fs from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import maxmind from 'maxmind';

export const MMDB_URL =
  'https://github.com/gen0sec/geoip-databases/releases/latest/download/ipinfo_lite.mmdb';

export const MMDB_MIN_BYTES = 1024 * 1024;

export type FetchFn = (url: string, init?: { redirect?: 'follow' }) => Promise<Response>;

export interface SyncOpts {
  file: string;
  fetchFn?: FetchFn;
  validate?: (file: string) => Promise<void>;
}

export type SyncResult = { ok: true; bytes: number } | { ok: false; error: string };

export async function opensAsMmdb(file: string): Promise<void> {
  await maxmind.open(file);
}

export async function mmdbBuildDate(file: string): Promise<Date> {
  return (await maxmind.open(file)).metadata.buildEpoch;
}

/** Downloads the MMDB to a temp file beside it, then renames it over `file` only if it checks out. */
export async function syncMmdb(opts: SyncOpts): Promise<SyncResult> {
  const fetchFn = opts.fetchFn ?? ((url, init) => fetch(url, init));
  const validate = opts.validate ?? opensAsMmdb;
  const tmp = `${opts.file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  try {
    const res = await fetchFn(MMDB_URL, { redirect: 'follow' });
    if (!res.ok || !res.body) throw new Error(`download failed: HTTP ${res.status}`);
    await pipeline(Readable.fromWeb(res.body as never), fs.createWriteStream(tmp));
    const bytes = fs.statSync(tmp).size;
    if (bytes < MMDB_MIN_BYTES) throw new Error(`download too small: ${bytes} bytes`);
    await validate(tmp);
    fs.renameSync(tmp, opts.file);
    return { ok: true, bytes };
  } catch (e) {
    fs.rmSync(tmp, { force: true });
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
