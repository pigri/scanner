import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, it, expect } from 'vitest';
import { writeFileAtomic } from '../src/lib/atomic-write.js';

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'atomic-write-'));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('writeFileAtomic', () => {
  it('writes the content and leaves no temp file', () => {
    const f = path.join(dir, 'domains.txt');
    writeFileAtomic(f, 'a.example.com\n');
    expect(fs.readFileSync(f, 'utf8')).toBe('a.example.com\n');
    expect(fs.readdirSync(dir)).toEqual(['domains.txt']);
  });

  it('replaces the target with a new inode (rename, not in-place rewrite)', () => {
    const f = path.join(dir, 'domains.txt');
    fs.writeFileSync(f, 'old\n');
    const before = fs.statSync(f).ino;
    writeFileAtomic(f, 'new\n');
    expect(fs.statSync(f).ino).not.toBe(before);
    expect(fs.readFileSync(f, 'utf8')).toBe('new\n');
  });

  it('keeps the old file and removes the temp when the write fails', () => {
    const f = path.join(dir, 'domains.txt');
    fs.writeFileSync(f, 'old\n');
    // a directory at the target makes the final rename fail
    const target = path.join(dir, 'sub');
    fs.mkdirSync(target);
    expect(() => writeFileAtomic(target, 'x')).toThrow();
    expect(fs.readFileSync(f, 'utf8')).toBe('old\n');
    expect(fs.readdirSync(dir).sort()).toEqual(['domains.txt', 'sub']);
  });
});
