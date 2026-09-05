import { describe, it, expect } from 'vitest';
import { formatLine } from '../src/lib/log.js';

const NOW = '2026-08-19T12:00:00.000Z';

describe('formatLine', () => {
  it('prefixes ISO timestamp and a padded level', () => {
    expect(formatLine('info', 'hello', NOW)).toBe('2026-08-19T12:00:00.000Z INFO  hello');
  });

  it('pads every level to 5 chars for column alignment', () => {
    expect(formatLine('warn', 'x', NOW)).toBe('2026-08-19T12:00:00.000Z WARN  x');
    expect(formatLine('error', 'x', NOW)).toBe('2026-08-19T12:00:00.000Z ERROR x');
    expect(formatLine('step', 'x', NOW)).toBe('2026-08-19T12:00:00.000Z STEP  x');
  });

  it('does not mangle the message body', () => {
    const msg = 'batch 1: claimed 1 row → in_progress';
    expect(formatLine('step', msg, NOW).endsWith(msg)).toBe(true);
  });
});
