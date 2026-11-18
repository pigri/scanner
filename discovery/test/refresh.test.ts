import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, it, expect } from 'vitest';
import { parseArgs, readEnrichRows, installEnrichOutputs } from '../src/refresh.js';

describe('refresh parseArgs', () => {
  it('defaults expand to false', () => {
    expect(parseArgs(['node', 'refresh']).expand).toBe(false);
  });

  it('--expand sets expand to true', () => {
    expect(parseArgs(['node', 'refresh', '--expand']).expand).toBe(true);
  });
});

describe('enrich output handling', () => {
  let dir: string;
  const p = (n: string) => path.join(dir, n);
  const row = (domain: string, addresses: string[]) => JSON.stringify({ domain, addresses }) + '\n';
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refresh-test-'));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('readEnrichRows reads the given file and ignores the shared enriched.jsonl', () => {
    fs.writeFileSync(p('enriched.jsonl'), row('other.example.com', ['192.0.2.9']));
    fs.writeFileSync(p('enriched.jsonl.tmp-1'), row('mine.example.com', ['192.0.2.1']) + '\n' + row('dead.example.com', []));
    const rows = readEnrichRows(p('enriched.jsonl.tmp-1'));
    expect(rows.map((r) => r.domain)).toEqual(['mine.example.com', 'dead.example.com']);
  });

  it('readEnrichRows returns [] for a missing file', () => {
    expect(readEnrichRows(p('nope.jsonl'))).toEqual([]);
  });

  const setup = () => {
    fs.writeFileSync(p('enriched.jsonl'), 'old-jsonl\n');
    fs.writeFileSync(p('enriched.csv'), 'old-csv\n');
    fs.writeFileSync(p('j.tmp'), 'new-jsonl\n');
    fs.writeFileSync(p('c.tmp'), 'new-csv\n');
    return { tmp: { jsonl: p('j.tmp'), csv: p('c.tmp') }, dest: { jsonl: p('enriched.jsonl'), csv: p('enriched.csv') } };
  };

  it('installEnrichOutputs(0) replaces both outputs', () => {
    const { tmp, dest } = setup();
    installEnrichOutputs(0, tmp, dest);
    expect(fs.readFileSync(dest.jsonl, 'utf8')).toBe('new-jsonl\n');
    expect(fs.readFileSync(dest.csv, 'utf8')).toBe('new-csv\n');
    expect(fs.existsSync(tmp.jsonl)).toBe(false);
    expect(fs.existsSync(tmp.csv)).toBe(false);
  });

  it('installEnrichOutputs(1) keeps the old outputs and removes the temps', () => {
    const { tmp, dest } = setup();
    installEnrichOutputs(1, tmp, dest);
    expect(fs.readFileSync(dest.jsonl, 'utf8')).toBe('old-jsonl\n');
    expect(fs.readFileSync(dest.csv, 'utf8')).toBe('old-csv\n');
    expect(fs.existsSync(tmp.jsonl)).toBe(false);
    expect(fs.existsSync(tmp.csv)).toBe(false);
  });
});
