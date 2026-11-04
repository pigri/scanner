import { describe, it, expect } from 'vitest';
import { minePatterns } from '../src/lib/patterns.js';

const corpus = [
  'efet.okfo.gov.hu',
  'newsletter.okfo.gov.hu',
  'michalicza.okfo.gov.hu',
  'web1.okfo.gov.hu',
  'web2.okfo.gov.hu',
];

describe('minePatterns', () => {
  it('groups names by registrable zone', () => {
    const g = minePatterns([...corpus, 'www.example.com']);
    expect(Object.keys(g.zones).sort()).toEqual(['example.com', 'okfo.gov.hu']);
  });

  it('counts word tokens per zone', () => {
    const z = minePatterns(corpus).zones['okfo.gov.hu'];
    expect(z).toBeDefined();
    expect(z!.names).toBe(5);
    const web = z!.tokens.find((t) => t.text === 'web');
    expect(web).toEqual({ text: 'web', count: 2, class: 'role' });
    const efet = z!.tokens.find((t) => t.text === 'efet');
    expect(efet).toEqual({ text: 'efet', count: 1, class: 'word' });
    expect(z!.tokens.some((t) => /^\d+$/.test(t.text))).toBe(false);
  });

  it('orders tokens by count desc then text', () => {
    const z = minePatterns(corpus).zones['okfo.gov.hu']!;
    expect(z.tokens.map((t) => t.text)).toEqual([
      'web',
      'efet',
      'michalicza',
      'newsletter',
    ]);
  });

  it('detects the web1/web2 numeric run', () => {
    const z = minePatterns(corpus).zones['okfo.gov.hu']!;
    expect(z.sequences).toEqual([{ template: 'web#', values: [1, 2], width: 0 }]);
  });

  it('records zero-padded width', () => {
    const z = minePatterns(['ns01.a.gov.hu', 'ns02.a.gov.hu', 'ns10.a.gov.hu']).zones['a.gov.hu']!;
    expect(z.sequences).toEqual([{ template: 'ns#', values: [1, 2, 10], width: 2 }]);
  });

  it('classifies suffix and region words and splits hyphenated labels', () => {
    const z = minePatterns(['efet-test2.okfo.gov.hu', 'eu.okfo.gov.hu']).zones['okfo.gov.hu']!;
    const cls = (s: string) => z.tokens.find((t) => t.text === s)?.class;
    expect(cls('test')).toBe('suffix');
    expect(cls('eu')).toBe('region');
    expect(z.sequences).toEqual([{ template: 'efet-test#', values: [2], width: 0 }]);
  });

  it('ignores the zone apex and is JSON round-trippable', () => {
    const g = minePatterns(['okfo.gov.hu', 'efet.okfo.gov.hu']);
    expect(g.zones['okfo.gov.hu']!.names).toBe(2);
    expect(JSON.parse(JSON.stringify(g))).toEqual(g);
  });
});
