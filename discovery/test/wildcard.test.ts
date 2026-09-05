import { describe, it, expect } from 'vitest';
import {
  WILDCARD_PROBE_LABELS,
  wildcardProbeHosts,
  classifyWildcard,
} from '../src/lib/wildcard.js';

describe('wildcardProbeHosts', () => {
  it('prefixes each fixed probe label onto the parent zone', () => {
    expect(wildcardProbeHosts('gov.hu')).toEqual([
      'zzzrand987nomatch.gov.hu',
      'xxx111notreal999.gov.hu',
    ]);
  });
  it('uses exactly the exported labels', () => {
    const hosts = wildcardProbeHosts('example.com');
    expect(hosts).toHaveLength(WILDCARD_PROBE_LABELS.length);
    for (const label of WILDCARD_PROBE_LABELS) {
      expect(hosts).toContain(`${label}.example.com`);
    }
  });
});

describe('classifyWildcard', () => {
  it('flags a wildcard when any probe answers', () => {
    const v = classifyWildcard('dtr.gov.hu', [['1.2.3.4'], []]);
    expect(v.wildcard).toBe(true);
    expect(v.ips).toEqual(['1.2.3.4']);
  });

  it('is clean when every probe returns nothing', () => {
    const v = classifyWildcard('clean.gov.hu', [[], []]);
    expect(v.wildcard).toBe(false);
    expect(v.ips).toEqual([]);
  });

  it('dedupes IPs across probes', () => {
    const v = classifyWildcard('w.gov.hu', [['1.2.3.4', '5.6.7.8'], ['1.2.3.4']]);
    expect(v.wildcard).toBe(true);
    expect(v.ips).toEqual(['1.2.3.4', '5.6.7.8']);
  });

  it('trims and drops blank answer lines', () => {
    const v = classifyWildcard('w.gov.hu', [['  1.2.3.4  ', ''], ['   ']]);
    expect(v.ips).toEqual(['1.2.3.4']);
  });

  it('carries the parent through untouched', () => {
    expect(classifyWildcard('a.b.gov.hu', [[]]).parent).toBe('a.b.gov.hu');
  });
});
