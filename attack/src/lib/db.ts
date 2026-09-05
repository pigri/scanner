import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface AttemptRow {
  target: string; protocol: string;
  username?: string | null; password?: string | null; nthash?: string | null; domain?: string | null;
  outcome: 'success' | 'fail' | 'locked' | 'error';
  privilege?: string | null; raw_line?: string | null;
}
export interface CredentialRow {
  source: string; target?: string | null;
  username?: string | null; domain?: string | null;
  hash_type?: string | null; hash_value?: string | null; password?: string | null;
}
export interface SessionRow {
  target: string; protocol: string;
  username?: string | null; privilege?: string | null;
  notes?: string | null;
}

export interface Db {
  raw: Database.Database;
  close(): void;
  startRun(tool: string, args: Record<string, unknown>, scopeAuthorized: boolean, atIso?: string): number;
  finishRun(id: number, atIso: string, notes?: string): void;
  insertAttempt(row: AttemptRow, atIso: string, runId: number | null): void;
  insertCredential(row: CredentialRow, atIso: string, runId: number | null): void;
  insertSession(row: SessionRow, atIso: string, runId: number | null): number;
  closeSession(id: number, atIso: string): void;
}

function loadSchema(): string {
  return fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
}

export function openDb(dbPath: string): Db {
  const raw = new Database(dbPath);
  raw.pragma('foreign_keys = ON');
  raw.exec(loadSchema());

  const startRunStmt = raw.prepare(
    'INSERT INTO runs(tool, started_at, args_json, scope_authorized) VALUES(?, ?, ?, ?)'
  );
  const finishRunStmt = raw.prepare(
    'UPDATE runs SET finished_at = ?, notes = ? WHERE id = ?'
  );
  const attemptStmt = raw.prepare(`
    INSERT INTO attempts(target, protocol, username, password, nthash, domain, outcome, privilege, raw_line, seen_at, run_id)
    VALUES(@target, @protocol, @username, @password, @nthash, @domain, @outcome, @privilege, @raw_line, @seen_at, @run_id)
  `);
  const credStmt = raw.prepare(`
    INSERT INTO credentials(source, target, username, domain, hash_type, hash_value, password, seen_at, run_id)
    VALUES(@source, @target, @username, @domain, @hash_type, @hash_value, @password, @seen_at, @run_id)
  `);
  const sessOpenStmt = raw.prepare(`
    INSERT INTO sessions(target, protocol, username, privilege, notes, opened_at, run_id)
    VALUES(@target, @protocol, @username, @privilege, @notes, @opened_at, @run_id)
  `);
  const sessCloseStmt = raw.prepare('UPDATE sessions SET closed_at = ? WHERE id = ?');

  return {
    raw,
    close(): void { raw.close(); },
    startRun(tool, args, scopeAuthorized, atIso): number {
      const info = startRunStmt.run(tool, atIso ?? new Date().toISOString(), JSON.stringify(args), scopeAuthorized ? 1 : 0);
      return Number(info.lastInsertRowid);
    },
    finishRun(id, atIso, notes): void {
      finishRunStmt.run(atIso, notes ?? null, id);
    },
    insertAttempt(row, atIso, runId): void {
      attemptStmt.run({
        target: row.target, protocol: row.protocol,
        username: row.username ?? null, password: row.password ?? null,
        nthash: row.nthash ?? null, domain: row.domain ?? null,
        outcome: row.outcome, privilege: row.privilege ?? null,
        raw_line: row.raw_line ?? null,
        seen_at: atIso, run_id: runId,
      });
    },
    insertCredential(row, atIso, runId): void {
      credStmt.run({
        source: row.source, target: row.target ?? null,
        username: row.username ?? null, domain: row.domain ?? null,
        hash_type: row.hash_type ?? null, hash_value: row.hash_value ?? null,
        password: row.password ?? null,
        seen_at: atIso, run_id: runId,
      });
    },
    insertSession(row, atIso, runId): number {
      const info = sessOpenStmt.run({
        target: row.target, protocol: row.protocol,
        username: row.username ?? null, privilege: row.privilege ?? null,
        notes: row.notes ?? null,
        opened_at: atIso, run_id: runId,
      });
      return Number(info.lastInsertRowid);
    },
    closeSession(id, atIso): void {
      sessCloseStmt.run(atIso, id);
    },
  };
}
