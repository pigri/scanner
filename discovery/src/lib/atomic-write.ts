import fs from 'node:fs';

let counter = 0;

/**
 * Write `data` to a temp file in the same directory, then rename it over
 * `file`. A concurrent reader sees the old or the new content, never a torn
 * file.
 */
export function writeFileAtomic(file: string, data: string): void {
  const tmp = `${file}.tmp-${process.pid}-${counter++}`;
  try {
    fs.writeFileSync(tmp, data);
    fs.renameSync(tmp, file);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
}
