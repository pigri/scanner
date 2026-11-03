import { describe, it, expect } from 'vitest';
import { parseLiveHosts } from '../src/lib/liveness.js';

// parseLiveHosts consumes naabu `-j` (JSONL) output: one
// {"host":"…","ip":"…","port":N} object per open port. probeLive spawns naabu
// (not httpx — see the rationale comment in liveness.ts), so these cases mirror
// what naabu actually emits, collapsed to distinct host/ip identifiers.
describe('parseLiveHosts', () => {
  it('extracts the host from naabu JSONL lines', () => {
    const out = '{"host":"a.gov.hu","ip":"1.2.3.4","port":443}\n{"host":"b.gov.hu","ip":"5.6.7.8","port":22}\n';
    expect([...parseLiveHosts(out)].sort()).toEqual(['a.gov.hu', 'b.gov.hu']);
  });

  it('collapses the many open-port lines of one host to a single id', () => {
    const out =
      '{"host":"a.gov.hu","ip":"1.2.3.4","port":80}\n' +
      '{"host":"a.gov.hu","ip":"1.2.3.4","port":443}\n' +
      '{"host":"a.gov.hu","ip":"1.2.3.4","port":22}\n';
    expect([...parseLiveHosts(out)]).toEqual(['a.gov.hu']);
  });

  it('falls back to ip when the row carries no host', () => {
    expect(parseLiveHosts('{"ip":"84.206.102.29","port":80}\n').has('84.206.102.29')).toBe(true);
  });

  it('lowercases and dedupes host ids', () => {
    const out = '{"host":"A.GOV.HU","ip":"1.2.3.4","port":443}\n{"host":"a.gov.hu","ip":"1.2.3.4","port":80}\n';
    expect([...parseLiveHosts(out)]).toEqual(['a.gov.hu']);
  });

  it('ignores blank lines, non-JSON lines and malformed JSON', () => {
    const out = '\n  \nnot json\n{"host":"a.gov.hu","port":443}\n{"host":"oops"\n';
    expect([...parseLiveHosts(out)]).toEqual(['a.gov.hu']);
  });

  it('returns empty for empty or whitespace-only input', () => {
    expect(parseLiveHosts('').size).toBe(0);
    expect(parseLiveHosts('\n\n  \n').size).toBe(0);
  });
});
