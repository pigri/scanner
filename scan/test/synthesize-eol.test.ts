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

  describe('tech-list (Wappalyzer) form', () => {
    const eolCats = (db: Db) => findings(db).filter((f) => f.category.startsWith('eol-'));
    const probeTech = (db: Db, web_server: string, tech: string[], target = 'host.example'): void => {
      db.insertHttpProbe({ target, url: `https://${target}/`, web_server, tech }, '2026-11-03T00:00:00Z', null);
    };

    it.each(['5.3.3', '5.6', '7.4.33', '7', '8.0.30', '8.0'])('flags tech PHP:%s as high eol-php', (v) => {
      const db = openDb(':memory:');
      probeTech(db, 'Apache', ['Bootstrap:3.2.0', `PHP:${v}`, 'jQuery']);
      runSynthesizeEol(db, NOW);
      expect(eolCats(db)).toEqual([{ target: 'host.example', category: 'eol-php', severity: 'high' }]);
    });

    it.each(['8.1.2', '8.3', '8.4.1', '8.10.0'])('does not flag tech PHP:%s', (v) => {
      const db = openDb(':memory:');
      probeTech(db, 'nginx', [`PHP:${v}`]);
      runSynthesizeEol(db, NOW);
      expect(eolCats(db)).toEqual([]);
    });

    it.each(['PHP/5.6', 'PHP/7', 'PHP/8.0.30'])('still flags header %s', (ws) => {
      const db = openDb(':memory:');
      probe(db, ws);
      runSynthesizeEol(db, NOW);
      expect(eolCats(db)).toEqual([{ target: 'host.example', category: 'eol-php', severity: 'high' }]);
    });

    it.each([
      ['Apache/2.2.15', []],
      ['Apache/2.0.64', []],
      ['Apache/1.3.42', []],
      ['', ['Apache HTTP Server:2.2.15']],
      ['', ['Apache HTTP Server:2.0.59']],
      ['', ['Apache HTTP Server:1.3.37']],
    ] as [string, string[]][])('flags web_server=%j tech=%j as high eol-apache', (ws, tech) => {
      const db = openDb(':memory:');
      probeTech(db, ws, tech);
      runSynthesizeEol(db, NOW);
      expect(eolCats(db)).toEqual([{ target: 'host.example', category: 'eol-apache', severity: 'high' }]);
    });

    it.each([
      ['Apache/2.4.58', []],
      ['', ['Apache HTTP Server:2.4.58']],
      ['Apache-Coyote/1.1', []],
      ['', ['Apache Tomcat:9.0.1']],
    ] as [string, string[]][])('does not flag web_server=%j tech=%j as EOL Apache', (ws, tech) => {
      const db = openDb(':memory:');
      probeTech(db, ws, tech);
      runSynthesizeEol(db, NOW);
      expect(eolCats(db)).toEqual([]);
    });

    it('keeps the low apache-version disclosure for the header form', () => {
      const db = openDb(':memory:');
      probe(db, 'Apache/2.2.15');
      runSynthesizeEol(db, NOW);
      expect(findings(db).map((f) => f.category)).toEqual(['apache-version', 'eol-apache']);
    });

    it('yields one finding per category when header and tech list disclose the same versions', () => {
      const db = openDb(':memory:');
      probeTech(db, 'Apache/2.2.15 (CentOS) PHP/5.3.3', ['Apache HTTP Server:2.2.15', 'PHP:5.3.3']);
      const r = runSynthesizeEol(db, NOW);
      expect(eolCats(db).map((f) => f.category)).toEqual(['eol-apache', 'eol-php']);
      expect(r.added).toBe(3); // eol-apache, eol-php, apache-version
      expect(runSynthesizeEol(db, NOW)).toMatchObject({ added: 0, skipped: 3 });
    });
  });
});
