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

    it.each(['OpenSSL:1.0.2k', 'OpenSSL:1.1.1w'])('flags tech %s as high eol-openssl', (t) => {
      const db = openDb(':memory:');
      probeTech(db, 'Apache', [t]);
      runSynthesizeEol(db, NOW);
      expect(eolCats(db)).toEqual([{ target: 'host.example', category: 'eol-openssl', severity: 'high' }]);
    });

    it('does not flag tech OpenSSL:3.0.13', () => {
      const db = openDb(':memory:');
      probeTech(db, 'Apache', ['OpenSSL:3.0.13']);
      runSynthesizeEol(db, NOW);
      expect(eolCats(db)).toEqual([]);
    });

    it.each(['Nginx:1.18.0', 'nginx:1.24.0'])('flags tech %s as low nginx-version', (t) => {
      const db = openDb(':memory:');
      probeTech(db, '', [t]);
      runSynthesizeEol(db, NOW);
      expect(findings(db)).toEqual([{ target: 'host.example', category: 'nginx-version', severity: 'low' }]);
    });

    it('yields one nginx-version finding when header and tech list disclose the same version', () => {
      const db = openDb(':memory:');
      probeTech(db, 'nginx/1.18.0', ['Nginx:1.18.0']);
      runSynthesizeEol(db, NOW);
      expect(findings(db)).toHaveLength(1);
    });

    it.each([
      [['CakePHP:4.4.14', 'Nginx', 'PHP:8.2.12']],
      [['PHP:8.1.2', 'ThinkPHP:5.0.24']],
      [['KPHP:5.1']],
    ] as [string[]][])('does not treat a product ending in PHP as PHP: %j', (tech) => {
      const db = openDb(':memory:');
      probeTech(db, 'nginx', tech);
      runSynthesizeEol(db, NOW);
      expect(eolCats(db)).toEqual([]);
    });

    it('does not match product names that merely end in openssl, nginx or apache', () => {
      const db = openDb(':memory:');
      probeTech(db, '', ['LibOpenSSL:1.0.2k', 'Xnginx:1.2.3', 'MyApache HTTP Server:2.2.15']);
      runSynthesizeEol(db, NOW);
      expect(findings(db)).toEqual([]);
    });

    it('still matches PHP inside JSON quotes and after a space in the header', () => {
      const db = openDb(':memory:');
      probeTech(db, 'X PHP/5.3.3', []);
      probeTech(db, '', ['PHP:5.3.3'], 'b.example');
      runSynthesizeEol(db, NOW);
      expect(eolCats(db)).toHaveLength(2);
      expect(eolCats(db)).toContainEqual({ target: 'host.example', category: 'eol-php', severity: 'high' });
      expect(eolCats(db)).toContainEqual({ target: 'b.example', category: 'eol-php', severity: 'high' });
    });

    it('reads probes with a NULL Server header: tech-only PHP:7.1.33 gives one eol-php finding', () => {
      const db = openDb(':memory:');
      db.insertHttpProbe({ target: 'host.example', url: 'https://host.example/', web_server: null, tech: ['PHP:7.1.33'] }, '2026-11-03T00:00:00Z', null);
      runSynthesizeEol(db, NOW);
      expect(findings(db)).toEqual([{ target: 'host.example', category: 'eol-php', severity: 'high' }]);
    });
  });
});
