#!/usr/bin/env -S node --loader tsx
// Resume scan-all in parallel, skipping the already-completed fast stages.
// testssl + nuclei run --live-only with tuned defaults. Replaces resume.sh.
import { runScanAll } from './lib/scan-all-runner.js';

runScanAll({
  targets: 'top100.txt',
  scope: 'scope.txt',
  sqlite: 'scan.db',
  skip: 'httpx,nmap,nuclei,takeover',
  testsslFlags: '--live-only --concurrency 6',
  nucleiFlags: '--live-only -c 50 --rate-limit 200 --timeout 5 --retries 1',
}).then((code) => process.exit(code));
