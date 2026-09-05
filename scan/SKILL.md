---
name: active-scan
description: Authorized red-team testing pipeline. Scripts live in scripts/. Follow-on to ddg-recon. Trigger — /active-scan or explicit ask.
---

# active-scan

Follow-on to [[ddg-recon]]. See `scripts/` for the TS codebase.

## Setup

1. Copy `scripts/` into a working dir under the engagement folder.
2. `npm install`, `npm test`.
3. Write a `scope.txt` (suffixes + CIDRs) authorizing targets.
4. Run `install-tools.sh` (sudo) to install external binaries.

## Run

```
npm run scan-all -- --targets domains.txt --scope scope.txt
```

Per-stage help: `npm run <stage> -- --help`.

Common flags: `--targets <file>`, `--scope <file>`, `--strict`, `-o <file>`, `--` to pass tool-native args.

`SKIP=<stage,stage> npm run scan-all -- ...` to skip stages.

## Discipline

- TDD in `src/lib/`, thin wrappers in `src/*.ts`.
- Scope-gate is warning-only by default. Written authorization from the target owner is the operator's responsibility.
- `.gitignore` covers all outputs and `scope.txt`.
