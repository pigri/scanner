import { describe, it, expect } from 'vitest';
import { parseHashLine, type ResponderHash } from '../src/lib/responder-parse.js';

describe('parseHashLine', () => {
  it('parses NTLMv2 line', () => {
    const l = 'alice::CORP:1122334455667788:aa'.padEnd(60, 'b') + ':cc'.padEnd(200, 'd');
    const r = parseHashLine(l, 'NTLMv2-SMB-192.168.1.5.txt');
    expect(r).not.toBeNull();
    expect(r!).toMatchObject<Partial<ResponderHash>>({
      source: 'responder-ntlmv2',
      user: 'alice',
      domain: 'CORP',
      hashType: 'NTLMv2',
    });
    expect(r!.hash.startsWith('alice::CORP:')).toBe(true);
  });

  it('captures empty domain', () => {
    const l = 'bob::' + ':1122334455667788:' + 'aabbccdd'.repeat(4) + ':' + 'eeff'.repeat(20);
    const r = parseHashLine(l, 'NTLMv2-HTTP-192.168.1.5.txt');
    expect(r).not.toBeNull();
    expect(r!.user).toBe('bob');
    expect(r!.domain).toBeNull();
  });

  it('null for lines that are not hashes', () => {
    expect(parseHashLine('some log message', 'foo.txt')).toBeNull();
    expect(parseHashLine('', 'foo.txt')).toBeNull();
    expect(parseHashLine('user::domain', 'foo.txt')).toBeNull();
  });

  it('derives source tag from the log filename prefix', () => {
    const l = 'x::y:1122334455667788:' + 'aabb'.repeat(4) + ':' + 'ccdd'.repeat(4);
    expect(parseHashLine(l, 'SMB-1.2.3.4.txt')!.source).toBe('responder-smb');
    expect(parseHashLine(l, 'HTTP-1.2.3.4.txt')!.source).toBe('responder-http');
    expect(parseHashLine(l, 'NTLMv2-SMB-1.2.3.4.txt')!.source).toBe('responder-ntlmv2');
  });
});
