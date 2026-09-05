import fs from 'node:fs';

// Small timestamped logger that tees to stderr and (optionally) a file. Used by
// the queue worker/enqueue so a run is observable live (tail -f the file) and
// auditable afterwards. formatLine is pure so it can be unit-tested.

export type Level = 'info' | 'warn' | 'error' | 'step';

export function formatLine(level: Level, msg: string, nowIso: string): string {
  return `${nowIso} ${level.toUpperCase().padEnd(5)} ${msg}`;
}

export interface Logger {
  info(msg: string): void;
  warn(msg: string): void;
  error(msg: string): void;
  step(msg: string): void;
  close(): void;
}

export function createLogger(opts: { file?: string | null } = {}): Logger {
  const fd = opts.file ? fs.openSync(opts.file, 'a') : null;
  const emit = (level: Level, msg: string): void => {
    const line = formatLine(level, msg, new Date().toISOString());
    process.stderr.write(line + '\n');
    if (fd !== null) fs.writeSync(fd, line + '\n');
  };
  return {
    info: (m) => emit('info', m),
    warn: (m) => emit('warn', m),
    error: (m) => emit('error', m),
    step: (m) => emit('step', m),
    close: () => { if (fd !== null) fs.closeSync(fd); },
  };
}
