import { describe, it, expect } from 'vitest';
import { extractCtHosts, expandNameValue, extractCertspotterHosts } from '../src/lib/ct.js';

describe('expandNameValue', () => {
  it('splits newline-separated SANs', () => {
    expect(expandNameValue('gitlab.dtr.gov.hu\nrunner.dtr.gov.hu')).toEqual([
      'gitlab.dtr.gov.hu',
      'runner.dtr.gov.hu',
    ]);
  });

  it('strips wildcard prefixes', () => {
    expect(expandNameValue('*.dtr.gov.hu')).toEqual(['dtr.gov.hu']);
  });

  it('trims whitespace and lowercases', () => {
    expect(expandNameValue('  Gitlab.DTR.gov.hu  \n  RUNNER.dtr.gov.hu ')).toEqual([
      'gitlab.dtr.gov.hu',
      'runner.dtr.gov.hu',
    ]);
  });

  it('ignores empty lines', () => {
    expect(expandNameValue('a.example.com\n\n\nb.example.com\n')).toEqual([
      'a.example.com',
      'b.example.com',
    ]);
  });

  it('returns [] for empty/null input', () => {
    expect(expandNameValue('')).toEqual([]);
    expect(expandNameValue(null)).toEqual([]);
    expect(expandNameValue(undefined)).toEqual([]);
  });
});

describe('extractCtHosts (crt.sh)', () => {
  it('extracts unique hosts from crt.sh JSON', () => {
    const response = [
      { name_value: 'gitlab.dtr.gov.hu\nrunner.dtr.gov.hu' },
      { name_value: 'gitlab.dtr.gov.hu' },
      { name_value: '*.dtr.gov.hu' },
      { name_value: 'ci.dtr.gov.hu' },
    ];
    expect(extractCtHosts(response).sort()).toEqual([
      'ci.dtr.gov.hu',
      'dtr.gov.hu',
      'gitlab.dtr.gov.hu',
      'runner.dtr.gov.hu',
    ]);
  });

  it('handles common_name fallback when name_value missing', () => {
    const response = [
      { common_name: 'apex.dtr.gov.hu' },
      { name_value: 'sub.dtr.gov.hu' },
    ];
    expect(extractCtHosts(response).sort()).toEqual([
      'apex.dtr.gov.hu',
      'sub.dtr.gov.hu',
    ]);
  });

  it('returns [] for empty or malformed input', () => {
    expect(extractCtHosts([])).toEqual([]);
    expect(extractCtHosts(null)).toEqual([]);
    expect(extractCtHosts({ error: 'nope' })).toEqual([]);
  });

  it('skips records with no usable fields', () => {
    const response = [
      { serial_number: 'x' },
      { name_value: '' },
      { name_value: 'good.example.com' },
    ];
    expect(extractCtHosts(response)).toEqual(['good.example.com']);
  });
});

describe('extractCertspotterHosts', () => {
  it('extracts unique hosts from certspotter dns_names', () => {
    const response = [
      { dns_names: ['*.dtr.gov.hu', 'dtr.gov.hu'] },
      { dns_names: ['gitlab.dtr.gov.hu', 'runner.dtr.gov.hu'] },
      { dns_names: ['gitlab.dtr.gov.hu'] }, // dup
    ];
    expect(extractCertspotterHosts(response).sort()).toEqual([
      'dtr.gov.hu',
      'gitlab.dtr.gov.hu',
      'runner.dtr.gov.hu',
    ]);
  });

  it('strips wildcards and lowercases', () => {
    const response = [{ dns_names: ['*.Example.COM', 'API.example.com'] }];
    expect(extractCertspotterHosts(response).sort()).toEqual([
      'api.example.com',
      'example.com',
    ]);
  });

  it('returns [] for malformed input', () => {
    expect(extractCertspotterHosts(null)).toEqual([]);
    expect(extractCertspotterHosts({})).toEqual([]);
    expect(extractCertspotterHosts([{}, { dns_names: null }])).toEqual([]);
  });
});
