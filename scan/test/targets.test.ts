import { describe, it, expect } from 'vitest';
import { parseTargets, splitTargets } from '../src/lib/targets.js';

describe('parseTargets', () => {
  it('reads one target per line, trims + dedupes + skips comments/blanks', () => {
    expect(
      parseTargets(`
      # comment
      example.com
        example.com
      foo.example.com

      # another
      1.2.3.4
    `)
    ).toEqual(['example.com', 'foo.example.com', '1.2.3.4']);
  });
});

describe('splitTargets', () => {
  it('separates hostnames from IPs', () => {
    const r = splitTargets(['foo.example.com', '1.2.3.4', 'bar.example.com', '2001:db8::1']);
    expect(r.hosts).toEqual(['foo.example.com', 'bar.example.com']);
    expect(r.ips).toEqual(['1.2.3.4', '2001:db8::1']);
  });
});
