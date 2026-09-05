import { spawn } from 'node:child_process';
import path from 'node:path';

// Shared launcher for the scan-all pipeline, used by the resume + scan-next
// entrypoints (which replaced resume.sh / scan-next.sh). The arg/env builders
// are pure so they can be unit-tested without spawning anything.

export interface ScanAllRunOpts {
  targets: string;
  scope: string;
  sqlite: string;
  skip?: string;         // SKIP env (comma-sep stage names)
  testsslFlags?: string; // TESTSSL_FLAGS env
  nucleiFlags?: string;  // NUCLEI_FLAGS env
  goBin?: string;        // extra dir to append to PATH (default: $HOME/go/bin)
}

export function scanAllArgs(o: ScanAllRunOpts): string[] {
  return ['tsx', 'src/scan-all.ts', '--targets', o.targets, '--scope', o.scope, '--sqlite', o.sqlite];
}

// Tuned production defaults for the slow stages: only probe live hosts, cap
// concurrency/rate so a batch can't melt the box or the target. Applied by any
// scan-all child unless the caller overrides via the environment.
export const TUNED_SCAN_FLAGS = {
  testsslFlags: '--live-only --concurrency 6',
  nucleiFlags: '--live-only -c 50 --rate-limit 200 --timeout 5 --retries 1',
} as const;

export interface ScanEnvDefaults {
  skip?: string;
  testsslFlags?: string;
  nucleiFlags?: string;
  goBin?: string;
}

/**
 * Build the env for a spawned scan-all child: ensure the Go tool dir is on PATH
 * (so httpx/nuclei/gowitness resolve without the caller exporting anything) and
 * apply flag defaults. Mirrors shell `${VAR:-default}`: a value already set in
 * `base` wins over the default, so env overrides still work.
 */
export function scanChildEnv(defaults: ScanEnvDefaults, base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const home = base['HOME'] ?? '';
  const goBin = defaults.goBin ?? (home ? path.join(home, 'go', 'bin') : '');
  const basePath = base['PATH'] ?? '';
  const env: NodeJS.ProcessEnv = { ...base };
  if (goBin && !basePath.split(path.delimiter).includes(goBin)) {
    env['PATH'] = basePath ? `${basePath}${path.delimiter}${goBin}` : goBin;
  }
  const setDefault = (key: string, val: string | undefined): void => {
    if (val === undefined) return;
    if (base[key] === undefined || base[key] === '') env[key] = val;
  };
  setDefault('SKIP', defaults.skip);
  setDefault('TESTSSL_FLAGS', defaults.testsslFlags);
  setDefault('NUCLEI_FLAGS', defaults.nucleiFlags);
  return env;
}

/** Back-compat wrapper used by the resume/scan-next runners. */
export function scanAllEnv(o: ScanAllRunOpts, base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  // Omit undefined keys (exactOptionalPropertyTypes forbids `{ skip: undefined }`).
  const d: ScanEnvDefaults = {};
  if (o.skip !== undefined) d.skip = o.skip;
  if (o.testsslFlags !== undefined) d.testsslFlags = o.testsslFlags;
  if (o.nucleiFlags !== undefined) d.nucleiFlags = o.nucleiFlags;
  if (o.goBin !== undefined) d.goBin = o.goBin;
  return scanChildEnv(d, base);
}

export function runScanAll(o: ScanAllRunOpts): Promise<number> {
  const args = scanAllArgs(o);
  const env = scanAllEnv(o);
  return new Promise((resolve) => {
    const child = spawn('npx', args, { stdio: 'inherit', env });
    child.on('close', (code) => resolve(code ?? 0));
  });
}
