import maxmind from 'maxmind';

/** Relative to the `scan/` working directory. */
export const DEFAULT_MMDB = '../discovery/ipinfo_lite.mmdb';
export const MMDB_STALE_DAYS = 7;

const MAX_FIELD = 200;
const FIELDS = ['asn', 'as_name', 'as_domain', 'country_code', 'country'] as const;

export interface GeoRow {
  asn?: string;
  as_name?: string;
  as_domain?: string;
  country_code?: string;
  country?: string;
}

export interface GeoLookup {
  get(ip: string): GeoRow | null;
  buildAt: string | null;
}

/** Keeps only the known fields that are non-empty strings, trimmed and capped. */
export function toGeoRow(rec: unknown): GeoRow | null {
  if (!rec || typeof rec !== 'object') return null;
  const src = rec as Record<string, unknown>;
  const out: GeoRow = {};
  for (const f of FIELDS) {
    const v = src[f];
    if (typeof v !== 'string') continue;
    const t = v.trim().slice(0, MAX_FIELD).trim();
    if (t) out[f] = t;
  }
  return Object.keys(out).length ? out : null;
}

interface MmdbReader {
  get(ip: string): unknown;
  metadata: { buildEpoch?: Date };
}

export function wrapReader(reader: MmdbReader): GeoLookup {
  const epoch = reader.metadata?.buildEpoch;
  const buildAt = epoch instanceof Date && !Number.isNaN(epoch.getTime()) ? epoch.toISOString() : null;
  return {
    buildAt,
    get(ip: string): GeoRow | null {
      try {
        return toGeoRow(reader.get(ip));
      } catch {
        return null;
      }
    },
  };
}

/** Never throws: a missing or unreadable database gives null. `onError` receives the reason. */
export async function openGeo(file: string, onError?: (err: unknown) => void): Promise<GeoLookup | null> {
  try {
    return wrapReader(await maxmind.open<Record<string, unknown>>(file));
  } catch (err) {
    try { onError?.(err); } catch { /* the contract is never to throw */ }
    return null;
  }
}
