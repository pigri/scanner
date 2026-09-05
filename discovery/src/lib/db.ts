import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import type { EnrichedRow, EnrichedAddress } from './graph.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface IpGeo {
  family: 4 | 6;
  asn?: string | null;
  as_name?: string | null;
  as_domain?: string | null;
  country_code?: string | null;
  country?: string | null;
  continent_code?: string | null;
}

export interface HostRow {
  id: number;
  name: string;
  first_seen: string;
  last_seen: string;
}

export interface RunArgs {
  [k: string]: unknown;
}

export interface RunFinish {
  addedHosts?: number;
  addedIps?: number;
  notes?: string;
  at?: string;
}

export interface Db {
  raw: Database.Database;
  close(): void;
  upsertHost(name: string, source: string, at: string): number;
  upsertIp(ip: string, geo: IpGeo, at: string): void;
  addResolution(hostId: number, ip: string, family: 4 | 6, at: string): void;
  addPtr(ip: string, name: string, at: string): void;
  hostsFirstSeenBetween(startIso: string | null, endIso: string | null): HostRow[];
  countBySource(): { source: string; n: number }[];
  startRun(tool: string, args: RunArgs, at?: string): number;
  finishRun(id: number, finish: RunFinish): void;
}

function loadSchema(): string {
  return fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
}

export interface ReadOpts {
  since?: string | null;
  until?: string | null;
}

interface JoinedRow {
  domain: string;
  first_seen: string;
  last_seen: string;
  ip: string;
  family: number;
  asn: string | null;
  as_name: string | null;
  as_domain: string | null;
  country_code: string | null;
  country: string | null;
  continent_code: string | null;
  ptr_names: string | null;
}

const READ_SQL = `
SELECT
  h.name        AS domain,
  h.first_seen  AS first_seen,
  h.last_seen   AS last_seen,
  r.ip          AS ip,
  r.family      AS family,
  i.asn, i.as_name, i.as_domain, i.country_code, i.country, i.continent_code,
  (SELECT GROUP_CONCAT(DISTINCT p.name)
     FROM ptr_records p
    WHERE p.ip = r.ip) AS ptr_names
FROM hosts h
JOIN resolutions r ON r.host_id = h.id
JOIN ips i         ON i.ip = r.ip
WHERE (@since IS NULL OR r.seen_at >= @since)
  AND (@until IS NULL OR r.seen_at <= @until)
GROUP BY h.id, r.ip
ORDER BY h.name, r.ip
`;

export function readEnrichedFromDb(db: Db, opts: ReadOpts = {}): EnrichedRow[] {
  const rows = db.raw
    .prepare(READ_SQL)
    .all({ since: opts.since ?? null, until: opts.until ?? null }) as JoinedRow[];
  const byDomain = new Map<string, EnrichedRow>();
  for (const r of rows) {
    let entry = byDomain.get(r.domain);
    if (!entry) {
      entry = { domain: r.domain, addresses: [], errors: [] };
      byDomain.set(r.domain, entry);
    }
    const addr: EnrichedAddress = {
      ip: r.ip,
      version: r.family === 6 ? 6 : 4,
      ptr: r.ptr_names ? r.ptr_names.split(',').filter(Boolean) : [],
      asn: r.asn,
      as_name: r.as_name,
      as_domain: r.as_domain,
      country_code: r.country_code,
      country: r.country,
      continent_code: r.continent_code,
    };
    entry.addresses.push(addr);
  }
  return [...byDomain.values()];
}

export function openDb(dbPath: string): Db {
  const raw = new Database(dbPath);
  raw.pragma('foreign_keys = ON');
  raw.exec(loadSchema());

  const insertHost = raw.prepare(
    'INSERT INTO hosts(name, first_seen, last_seen) VALUES(?, ?, ?)'
  );
  const findHost = raw.prepare('SELECT id, first_seen FROM hosts WHERE name = ?');
  const touchHost = raw.prepare('UPDATE hosts SET last_seen = ? WHERE id = ?');
  const insertSource = raw.prepare(
    'INSERT INTO sources(host_id, source, seen_at) VALUES(?, ?, ?)'
  );

  const upsertHost = raw.transaction((name: string, source: string, at: string): number => {
    const existing = findHost.get(name) as { id: number; first_seen: string } | undefined;
    let id: number;
    if (existing) {
      touchHost.run(at, existing.id);
      id = existing.id;
    } else {
      const info = insertHost.run(name, at, at);
      id = Number(info.lastInsertRowid);
    }
    insertSource.run(id, source, at);
    return id;
  });

  const upsertIpStmt = raw.prepare(`
    INSERT INTO ips(ip, family, asn, as_name, as_domain, country_code, country, continent_code, first_seen, last_seen)
    VALUES(@ip, @family, @asn, @as_name, @as_domain, @country_code, @country, @continent_code, @at, @at)
    ON CONFLICT(ip) DO UPDATE SET
      family = excluded.family,
      asn = excluded.asn,
      as_name = excluded.as_name,
      as_domain = excluded.as_domain,
      country_code = excluded.country_code,
      country = excluded.country,
      continent_code = excluded.continent_code,
      last_seen = excluded.last_seen
  `);
  const addResolutionStmt = raw.prepare(
    'INSERT INTO resolutions(host_id, ip, family, seen_at) VALUES(?, ?, ?, ?)'
  );
  const addPtrStmt = raw.prepare(
    'INSERT INTO ptr_records(ip, name, seen_at) VALUES(?, ?, ?)'
  );

  const startRunStmt = raw.prepare(
    'INSERT INTO runs(tool, started_at, args_json) VALUES(?, ?, ?)'
  );
  const finishRunStmt = raw.prepare(
    'UPDATE runs SET finished_at = ?, added_hosts = ?, added_ips = ?, notes = ? WHERE id = ?'
  );

  const hostsInRangeAll = raw.prepare(
    'SELECT id, name, first_seen, last_seen FROM hosts ORDER BY first_seen'
  );
  const hostsInRangeBoth = raw.prepare(
    'SELECT id, name, first_seen, last_seen FROM hosts WHERE first_seen >= ? AND first_seen <= ? ORDER BY first_seen'
  );
  const hostsInRangeFrom = raw.prepare(
    'SELECT id, name, first_seen, last_seen FROM hosts WHERE first_seen >= ? ORDER BY first_seen'
  );
  const hostsInRangeTo = raw.prepare(
    'SELECT id, name, first_seen, last_seen FROM hosts WHERE first_seen <= ? ORDER BY first_seen'
  );

  const countBySourceStmt = raw.prepare(
    'SELECT source, COUNT(DISTINCT host_id) as n FROM sources GROUP BY source ORDER BY n DESC'
  );

  return {
    raw,
    close(): void { raw.close(); },
    upsertHost,
    upsertIp(ip, geo, at): void {
      upsertIpStmt.run({
        ip, family: geo.family, at,
        asn: geo.asn ?? null,
        as_name: geo.as_name ?? null,
        as_domain: geo.as_domain ?? null,
        country_code: geo.country_code ?? null,
        country: geo.country ?? null,
        continent_code: geo.continent_code ?? null,
      });
    },
    addResolution(hostId, ip, family, at): void {
      addResolutionStmt.run(hostId, ip, family, at);
    },
    addPtr(ip, name, at): void {
      addPtrStmt.run(ip, name, at);
    },
    hostsFirstSeenBetween(startIso, endIso): HostRow[] {
      if (startIso && endIso) return hostsInRangeBoth.all(startIso, endIso) as HostRow[];
      if (startIso) return hostsInRangeFrom.all(startIso) as HostRow[];
      if (endIso) return hostsInRangeTo.all(endIso) as HostRow[];
      return hostsInRangeAll.all() as HostRow[];
    },
    countBySource(): { source: string; n: number }[] {
      return countBySourceStmt.all() as { source: string; n: number }[];
    },
    startRun(tool, args, at): number {
      const info = startRunStmt.run(tool, at ?? new Date().toISOString(), JSON.stringify(args));
      return Number(info.lastInsertRowid);
    },
    finishRun(id, finish): void {
      finishRunStmt.run(
        finish.at ?? new Date().toISOString(),
        finish.addedHosts ?? 0,
        finish.addedIps ?? 0,
        finish.notes ?? null,
        id
      );
    },
  };
}
