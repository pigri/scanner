import { describe, it, expect } from 'vitest';
import { defaultNvdDb } from '../src/version-match.js';

describe('defaultNvdDb', () => {
  it('keeps the historical default when SCAN_DATA_DIR is unset', () => {
    expect(defaultNvdDb({})).toBe('/storage/gen0sec-scan/nvd.db');
  });
  it('treats an empty SCAN_DATA_DIR as unset', () => {
    expect(defaultNvdDb({ SCAN_DATA_DIR: '' })).toBe('/storage/gen0sec-scan/nvd.db');
  });
  it('derives the path from SCAN_DATA_DIR when set', () => {
    expect(defaultNvdDb({ SCAN_DATA_DIR: '/srv/scan-data' })).toBe('/srv/scan-data/nvd.db');
  });
  it('does not double the slash for a trailing separator', () => {
    expect(defaultNvdDb({ SCAN_DATA_DIR: '/srv/scan-data/' })).toBe('/srv/scan-data/nvd.db');
  });
});
