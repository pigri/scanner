#!/usr/bin/env -S node --loader tsx
// Run scan-all on the second batch (top100-next.txt) -> same scan.db.
// testssl + nuclei run --live-only with tighter defaults so dead hosts don't
// burn hours. Replaces scan-next.sh.
import { runScanAll } from './lib/scan-all-runner.js';

runScanAll({
  targets: 'top100-next.txt',
  scope: 'scope.txt',
  sqlite: 'scan.db',
  testsslFlags: '--live-only --concurrency 6',
  nucleiFlags: '--live-only -c 50 --rate-limit 200 --timeout 5 --retries 1',
}).then((code) => process.exit(code));
