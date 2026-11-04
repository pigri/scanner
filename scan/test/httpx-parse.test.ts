import { describe, it, expect } from 'vitest';
import { parseHttpxRow } from '../src/lib/httpx-parse.js';

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
});
