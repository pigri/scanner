import { describe, it, expect } from 'vitest';
import {
  parseSearchResponse,
  ipv4RangeToCidrs,
  ipv4ToInt,
  extractCidrs,
  extractAsn,
  extractOrg,
  hasCountry,
  hasOrgRef,
  buildSearchUrl,
  type RipeObject,
} from '../src/lib/ripe-search.js';

const doc = (attrs: Record<string, string | string[]>): { doc: { strs: { str: { name: string; value: string } }[] } } => ({
  doc: {
    strs: Object.entries(attrs).flatMap(([name, v]) =>
      (Array.isArray(v) ? v : [v]).map((value) => ({ str: { name, value } })),
    ),
  },
});

describe('ipv4ToInt', () => {
  it('handles the boundary and typical values', () => {
    expect(ipv4ToInt('0.0.0.0')).toBe(0);
    expect(ipv4ToInt('255.255.255.255')).toBe(0xffffffff);
    expect(ipv4ToInt('84.206.0.0')).toBe(1422786560); // 84*2^24 + 206*2^16
  });
  it('rejects malformed input', () => {
    expect(() => ipv4ToInt('1.2.3')).toThrow(/invalid IPv4/);
    expect(() => ipv4ToInt('300.1.1.1')).toThrow(/invalid IPv4/);
    expect(() => ipv4ToInt('a.b.c.d')).toThrow(/invalid IPv4/);
  });
});

describe('ipv4RangeToCidrs', () => {
  it('handles a single /24 aligned range', () => {
    expect(ipv4RangeToCidrs('193.224.43.0 - 193.224.43.255')).toEqual(['193.224.43.0/24']);
  });
  it('handles a /16 aligned range', () => {
    expect(ipv4RangeToCidrs('84.206.0.0 - 84.206.255.255')).toEqual(['84.206.0.0/16']);
  });
  it('decomposes a non-aligned range into multiple blocks', () => {
    // 1.2.3.4 - 1.2.3.7 → /30 (contains .4-.7)
    expect(ipv4RangeToCidrs('1.2.3.4 - 1.2.3.7')).toEqual(['1.2.3.4/30']);
    // 1.2.3.5 - 1.2.3.10 → /32, /31, /30, /32
    expect(ipv4RangeToCidrs('1.2.3.5 - 1.2.3.10')).toEqual([
      '1.2.3.5/32', '1.2.3.6/31', '1.2.3.8/31', '1.2.3.10/32',
    ]);
  });
  it('passes through bare CIDR notation', () => {
    expect(ipv4RangeToCidrs('10.0.0.0/8')).toEqual(['10.0.0.0/8']);
  });
  it('promotes a bare address to /32', () => {
    expect(ipv4RangeToCidrs('192.0.2.1')).toEqual(['192.0.2.1/32']);
  });
  it('rejects inverted ranges', () => {
    expect(() => ipv4RangeToCidrs('1.2.3.10 - 1.2.3.5')).toThrow(/inverted/);
  });
});

describe('parseSearchResponse', () => {
  it('normalises the RIPE envelope + multi-value attrs', () => {
    const raw = {
      result: {
        numFound: 3,
        docs: [
          doc({
            'object-type': 'inetnum',
            'primary-key': '999',
            'inetnum': '193.224.43.0 - 193.224.43.255',
            'netname': 'NISZ-WDC-NET',
            'country': 'HU',
            'descr': ['NISZ Zrt.', 'Government cloud'],
            'org': 'ORG-NISZ1-RIPE',
          }),
        ],
      },
    };
    const parsed = parseSearchResponse(raw);
    expect(parsed.numFound).toBe(3);
    expect(parsed.docs).toHaveLength(1);
    const d = parsed.docs[0]!;
    expect(d.type).toBe('inetnum');
    expect(d.primaryKey).toBe('999');
    expect(d.attrs.descr).toEqual(['NISZ Zrt.', 'Government cloud']);
    expect(d.attrs.netname).toEqual(['NISZ-WDC-NET']);
  });
  it('falls back to the "response" envelope', () => {
    const raw = {
      response: {
        numFound: 1,
        docs: [doc({ 'object-type': 'aut-num', 'primary-key': 'AS12345', 'aut-num': 'AS12345' })],
      },
    };
    expect(parseSearchResponse(raw).numFound).toBe(1);
  });
  it('skips docs without object-type', () => {
    const raw = { result: { numFound: 1, docs: [doc({ 'primary-key': 'x' })] } };
    expect(parseSearchResponse(raw).docs).toHaveLength(0);
  });
  it('handles empty / malformed input safely', () => {
    expect(parseSearchResponse(null).docs).toEqual([]);
    expect(parseSearchResponse({}).docs).toEqual([]);
    expect(parseSearchResponse({ result: {} }).docs).toEqual([]);
  });
});

describe('extractors + filters', () => {
  const inetnum: RipeObject = {
    type: 'inetnum',
    primaryKey: '1',
    attrs: { inetnum: ['84.206.0.0 - 84.206.255.255'], country: ['HU'], org: ['ORG-KL2-RIPE'] },
  };
  const inet6num: RipeObject = {
    type: 'inet6num',
    primaryKey: '2',
    attrs: { inet6num: ['2001:1234::/32'], country: ['hu'] },
  };
  const autnum: RipeObject = {
    type: 'aut-num',
    primaryKey: 'AS29761',
    attrs: { 'aut-num': ['AS29761'], descr: ['KIFU-ASN'] },
  };
  const org: RipeObject = {
    type: 'organisation',
    primaryKey: 'ORG-NISZ1-RIPE',
    attrs: { organisation: ['ORG-NISZ1-RIPE'], 'org-name': ['NISZ Zrt.'], country: ['HU'] },
  };

  it('extractCidrs handles inetnum ranges and inet6num CIDRs', () => {
    expect(extractCidrs(inetnum)).toEqual(['84.206.0.0/16']);
    expect(extractCidrs(inet6num)).toEqual(['2001:1234::/32']);
    expect(extractCidrs(autnum)).toEqual([]);
    expect(extractCidrs(org)).toEqual([]);
  });
  it('extractAsn returns AS handle only for aut-num', () => {
    expect(extractAsn(autnum)).toBe('AS29761');
    expect(extractAsn(inetnum)).toBeNull();
  });
  it('extractOrg returns org handle only for organisation', () => {
    expect(extractOrg(org)).toBe('ORG-NISZ1-RIPE');
    expect(extractOrg(inetnum)).toBeNull();
  });
  it('hasCountry is case-insensitive on both sides', () => {
    expect(hasCountry(inetnum, 'HU')).toBe(true);
    expect(hasCountry(inetnum, 'hu')).toBe(true);
    expect(hasCountry(inet6num, 'HU')).toBe(true); // stored lowercase
    expect(hasCountry(inetnum, 'PL')).toBe(false);
    expect(hasCountry(autnum, 'HU')).toBe(false); // no country attr
  });
  it('hasOrgRef matches on the org attribute', () => {
    expect(hasOrgRef(inetnum, 'ORG-KL2-RIPE')).toBe(true);
    expect(hasOrgRef(inetnum, 'org-kl2-ripe')).toBe(true);
    expect(hasOrgRef(inetnum, 'ORG-OTHER-RIPE')).toBe(false);
  });
});

describe('buildSearchUrl', () => {
  it('composes terms with OR and quotes multi-word terms', () => {
    const url = buildSearchUrl(['kormany', 'gov.hu', 'NISZ Zrt'], ['inetnum', 'aut-num'], 50);
    const q = new URL(url).searchParams.get('q')!;
    expect(q).toBe('(kormany OR gov.hu OR "NISZ Zrt") AND (object-type:inetnum OR object-type:aut-num)');
    expect(new URL(url).searchParams.get('rows')).toBe('50');
  });
  it('drops the type clause when types is empty', () => {
    const url = buildSearchUrl(['gov.hu'], [], 10);
    expect(new URL(url).searchParams.get('q')).toBe('(gov.hu)');
  });
  it('rejects empty term list', () => {
    expect(() => buildSearchUrl([], ['inetnum'], 10)).toThrow(/at least one/);
  });
});
