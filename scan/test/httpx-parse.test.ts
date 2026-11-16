import { describe, it, expect } from 'vitest';
import { parseHttpxRow, ingestHttpxOutput } from '../src/lib/httpx-parse.js';
import { openDb } from '../src/lib/db.js';

const row = (o: Record<string, unknown>): string =>
  JSON.stringify({ host: 'a.example', url: 'https://a.example', ...o });

describe('parseHttpxRow', () => {
  it('uses webserver when set', () => {
    expect(parseHttpxRow(row({ webserver: 'nginx' }))?.web_server).toBe('nginx');
  });
  it('accepts the web-server key', () => {
    expect(parseHttpxRow(row({ 'web-server': 'Apache' }))?.web_server).toBe('Apache');
  });
  it('webserver beats header.server', () => {
    const p = parseHttpxRow(row({ webserver: 'nginx', header: { server: 'MinIO' } }));
    expect(p?.web_server).toBe('nginx');
  });
  it('returns null web_server when no source is present', () => {
    expect(parseHttpxRow(row({}))?.web_server).toBeNull();
  });
  it('normalizes target to the bare lowercase hostname', () => {
    expect(parseHttpxRow(JSON.stringify({ input: 'HTTPS://Foo.Example.:8443/x', url: 'u' }))?.target).toBe('foo.example');
  });
  it('returns null for blank and garbage lines', () => {
    expect(parseHttpxRow('')).toBeNull();
    expect(parseHttpxRow('   ')).toBeNull();
    expect(parseHttpxRow('not json')).toBeNull();
  });
  it('falls back to header.server', () => {
    expect(parseHttpxRow(row({ header: { server: 'MinIO' } }))?.web_server).toBe('MinIO');
  });
  it('falls back to header.Server', () => {
    expect(parseHttpxRow(row({ header: { Server: 'MinIO' } }))?.web_server).toBe('MinIO');
  });
  it.each(['null', '[]', '5', '"x"', 'true'])('returns null for the non-object JSON line %s', (line) => {
    expect(parseHttpxRow(line)).toBeNull();
  });
  it('returns null when host is not a string and nothing else names a target', () => {
    expect(parseHttpxRow('{"host":5}')).toBeNull();
  });
  it('treats a non-string host as empty without falling back to input', () => {
    expect(parseHttpxRow('{"host":5,"input":"b.example"}')).toBeNull();
  });
  it('treats a non-string url as empty', () => {
    expect(parseHttpxRow('{"host":"a.example","url":{"x":1}}')?.url).toBe('');
    expect(parseHttpxRow('{"url":7}')).toBeNull();
  });
});

describe('ingestHttpxOutput', () => {
  it('stores both good rows around a junk line', () => {
    const db = openDb(':memory:');
    const runId = db.startRun('httpx', { targets: 2, extraArgs: [] }, '2026-01-01T00:00:00Z');
    const text = [row({ host: 'a.example' }), 'null', '{"host":5}', row({ host: 'b.example' }), ''].join('\n');
    expect(ingestHttpxOutput(db, text, '2026-01-01T00:00:00Z', runId)).toBe(2);
    db.close();
  });
});
