# Running the scan pipeline as daemons

Two decoupled stages, each a `--watch` daemon draining its own SQLite queue:

```
enqueue ─▶ scan_queue ─▶ [scan worker(s)] ─▶ report_queue ─▶ [report worker] ─▶ reports/*.md
```

- **scan worker** (`worker.ts`): claim from `scan_queue` → run `scan-all` →
  mark done → hand the target off to `report_queue`.
- **report worker** (`report-worker.ts`): claim from `report_queue` → write a
  per-target markdown report to `--out-dir`.

**Multi-scanner:** you can run several scan workers against the same `scan.db`.
The DB is WAL-mode with `busy_timeout`, and `claimBatch` uses an IMMEDIATE
transaction, so concurrent workers serialize their writes and never double-claim
a target. SQLite stays the single source of truth (one writer at a time).

Run everything under **systemd (user services)** so they restart on failure and
survive logout.

## Install (user service, no root)

```bash
# 1. Link both units into the user systemd dir
mkdir -p ~/.config/systemd/user
ln -sf ~/gen0sec/redteam/scan/deploy/scan-worker.service        ~/.config/systemd/user/scan-worker.service
ln -sf ~/gen0sec/redteam/scan/deploy/scan-report-worker.service ~/.config/systemd/user/scan-report-worker.service

# 2. Keep them running without an active login session
loginctl enable-linger "$USER"

# 3. Enable + start
systemctl --user daemon-reload
systemctl --user enable --now scan-worker scan-report-worker
```

## Scheduling (daily new hosts + weekly full re-scan)

With the workers running as daemons, three **systemd timers** feed them:

- **`nuclei-update-templates.timer`** (daily 02:30): `nuclei -update-templates`
  so any subsequent scan uses the day's fresh template set. Safe mid-scan —
  nuclei loads templates at process start.
- **`scan-feed.timer`** (daily 03:00): refresh recon → enqueue **new** hosts
  (already-scanned hosts are skipped, so only newly-discovered infra is queued).
- **`scan-rescan.timer`** (weekly, Sun 04:00): `enqueue --requeue` **all** known
  hosts (resets them to pending) so the scanner re-checks them for new findings
  — new nuclei templates, changed services, etc.

Both use `Persistent=true`, so a run missed while the box was off fires on next boot.

```bash
# link the feeder units + timers
for u in scan-feed.service scan-feed.timer scan-rescan.service scan-rescan.timer \
         nuclei-update-templates.service nuclei-update-templates.timer; do
  ln -sf ~/gen0sec/redteam/scan/deploy/$u ~/.config/systemd/user/$u
done
systemctl --user daemon-reload
systemctl --user enable --now scan-feed.timer scan-rescan.timer nuclei-update-templates.timer

# inspect
systemctl --user list-timers                 # next fire times
journalctl --user -u scan-feed -f            # last recon+enqueue run
systemctl --user start scan-feed             # run the daily cycle right now (test)
```

The flow end to end:

```
scan-feed.timer  (daily)  ─▶ refresh recon ─▶ enqueue NEW hosts ─┐
scan-rescan.timer (weekly)─▶ enqueue --requeue ALL hosts ────────┤
                                                                 ▼
                                                    scan_queue (WAL)
                                                                 │  scan-worker@1..N (always on)
                                                                 ▼
                                                    report_queue ─▶ report-worker ─▶ reports/*.md
```

## Multiple scanners

Run N scan workers as templated instances (all safe against one WAL `scan.db`):

```bash
# systemd instance units share one file via '@'
ln -sf ~/gen0sec/redteam/scan/deploy/scan-worker.service ~/.config/systemd/user/scan-worker@.service
systemctl --user start scan-worker@1 scan-worker@2 scan-worker@3
```

The report worker stays a single instance (it only writes report files).

## Operate

```bash
systemctl --user status scan-worker      # health + last logs
journalctl --user -u scan-worker -f      # live journal
tail -f ~/gen0sec/redteam/scan/logs/worker.service.log   # tee'd audit log
systemctl --user restart scan-worker
systemctl --user stop scan-worker        # SIGTERM: finishes the in-flight batch first
```

Enqueue work at any time; the running daemon picks it up within one poll interval:

```bash
npm run enqueue -- --from-risk 200 --sqlite scan.db
# or a single host:
npm run enqueue -- some.host.gov.hu --sqlite scan.db
```

## Notes

- The unit runs `--watch --scope scope.txt`; edit `ExecStart` to change batch
  size (`--batch-size N`), poll interval (`--poll-interval S`), or scope.
- Interrupted batches leave their rows `in_progress`. Requeue with:
  `UPDATE scan_queue SET status='pending' WHERE status='in_progress';`
- `ExecStart` sources `~/.nvm/nvm.sh` explicitly so nvm-managed node/npx resolve
  under systemd's clean environment (a login shell alone does not, because nvm
  lives in `~/.bashrc`). If you use a system node instead, replace the
  `export NVM_DIR=...; . nvm.sh;` prefix with the absolute `npx` path.
- `ExecStart` also sources `.env.scan` (from the scan dir) if present, so
  `WPSCAN_API_TOKEN` and any other per-operator secrets reach the wpscan child
  without being baked into the unit. See `.env.scan.example` for the template.
