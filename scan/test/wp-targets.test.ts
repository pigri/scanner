import { describe, it, expect } from 'vitest';
import { wpTargetsFromHttpx } from '../src/lib/wp-targets.js';

const line = (o: Record<string, unknown>): string => JSON.stringify(o);
const wp = (host: string, extra: Record<string, unknown> = {}): string =>
  line({ host, url: `https://${host}`, tech: ['WordPress', 'PHP'], ...extra });

describe('wpTargetsFromHttpx', () => {
  it('drops a WordPress row whose host is outside the batch', () => {
    const text = [wp('other.example.com'), wp('a.example.com')].join('\n');
    expect(wpTargetsFromHttpx([text], ['a.example.com'])).toEqual(['https://a.example.com']);
  });

  it('keeps a WordPress row inside the batch', () => {
    expect(wpTargetsFromHttpx([wp('a.example.com')], ['a.example.com'])).toEqual(['https://a.example.com']);
  });

  it('drops a row that is not WordPress', () => {
    const text = line({ host: 'a.example.com', url: 'https://a.example.com', tech: ['nginx'] });
    expect(wpTargetsFromHttpx([text], ['a.example.com'])).toEqual([]);
  });

  it('matches across scheme, port and case in the row and in the batch', () => {
    const text = wp('x', { host: undefined, input: 'https://WWW.example.com:8443', url: 'https://WWW.example.com:8443/' });
    expect(wpTargetsFromHttpx([text], ['www.example.com'])).toEqual(['https://WWW.example.com:8443/']);
    expect(wpTargetsFromHttpx([text], ['HTTP://Www.Example.com:80/blog'])).toEqual(['https://WWW.example.com:8443/']);
  });

  it('collapses duplicates across texts and keeps first-seen order', () => {
    const a = [wp('b.example.com'), wp('a.example.com')].join('\n');
    const b = [wp('a.example.com'), wp('c.example.com')].join('\n');
    expect(wpTargetsFromHttpx([a, b], ['a.example.com', 'b.example.com', 'c.example.com'])).toEqual([
      'https://b.example.com', 'https://a.example.com', 'https://c.example.com',
    ]);
  });

  it('skips malformed and blank lines', () => {
    const text = ['{not json', '', '[1]', wp('a.example.com')].join('\n');
    expect(wpTargetsFromHttpx([text], ['a.example.com'])).toEqual(['https://a.example.com']);
  });
});
