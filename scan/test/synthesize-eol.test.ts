import { describe, it, expect } from 'vitest';
import { openDb, type Db } from '../src/lib/db.js';
import { runSynthesizeEol } from '../src/synthesize-eol.js';

const NOW = '2026-11-04T00:00:00.000Z';

function probe(db: Db, web_server: string, target = 'host.example'): void {
  db.insertHttpProbe({ target, url: `https://${target}/`, web_server, tech: [] }, '2026-11-03T00:00:00Z', null);
}

const findings = (db: Db) =>
  db.raw.prepare("SELECT target, category, severity FROM findings WHERE tool='synthesize-eol' ORDER BY category").all() as
    { target: string; category: string; severity: string }[];

describe('runSynthesizeEol', () => {
  it('is idempotent: a second run adds nothing and skips the existing finding', () => {
    const db = openDb(':memory:');
    probe(db, 'MinIO');
    const first = runSynthesizeEol(db, NOW);
    const second = runSynthesizeEol(db, '2026-11-05T00:00:00.000Z');
    expect(first).toMatchObject({ added: 1, skipped: 0 });
    expect(second).toMatchObject({ added: 0, skipped: 1 });
    expect(findings(db).filter((f) => f.category === 'eol-minio')).toHaveLength(1);
    const seen = db.raw.prepare("SELECT seen_at FROM findings WHERE tool='synthesize-eol'").all() as { seen_at: string }[];
    expect(seen[0]!.seen_at).toBe(NOW);
  });

  it.each(['MinIO', 'MinIO Console'])('flags web_server=%s as high eol-minio', (ws) => {
    const db = openDb(':memory:');
    probe(db, ws);
    runSynthesizeEol(db, NOW);
    expect(findings(db)).toEqual([{ target: 'host.example', category: 'eol-minio', severity: 'high' }]);
  });

  it('still flags EOL OpenSSL and PHP', () => {
    const db = openDb(':memory:');
    probe(db, 'Apache OpenSSL/1.0.2k', 'a.example');
    probe(db, 'PHP/7.4.3', 'b.example');
    runSynthesizeEol(db, NOW);
    const f = findings(db);
    expect(f).toContainEqual({ target: 'a.example', category: 'eol-openssl', severity: 'high' });
    expect(f).toContainEqual({ target: 'b.example', category: 'eol-php', severity: 'high' });
  });

  it('does not flag benign nginx as EOL', () => {
    const db = openDb(':memory:');
    probe(db, 'nginx/1.24.0');
    runSynthesizeEol(db, NOW);
    expect(findings(db).filter((f) => f.category.startsWith('eol-'))).toEqual([]);
  });
});
