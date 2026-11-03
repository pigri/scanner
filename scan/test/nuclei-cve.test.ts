import { describe, it, expect } from 'vitest';
import { cveIdsFor } from '../src/lib/nuclei-cve.js';

describe('cveIdsFor', () => {
  it('records EVERY cve id of a multi-CVE template, not just the first', () => {
    // The bug: a template like PHP2Shell lists two CVEs but only the first was
    // ever stored. Both must be recorded so secondary CVEs are not lost.
    expect(cveIdsFor(['CVE-2026-109618', 'CVE-2026-109619'])).toEqual([
      'CVE-2026-109618',
      'CVE-2026-109619',
    ]);
  });

  it('records a single cve id as a one-element list', () => {
    expect(cveIdsFor(['CVE-2020-15081'])).toEqual(['CVE-2020-15081']);
  });

  it('yields [null] when there is no cve (so the finding is still recorded)', () => {
    expect(cveIdsFor(undefined)).toEqual([null]);
    expect(cveIdsFor(null)).toEqual([null]);
    expect(cveIdsFor([])).toEqual([null]);
  });

  it('trims and drops empty/whitespace ids', () => {
    expect(cveIdsFor([' CVE-2026-1 ', '', '   ', 'CVE-2026-2'])).toEqual(['CVE-2026-1', 'CVE-2026-2']);
    expect(cveIdsFor(['  '])).toEqual([null]);
  });
});
