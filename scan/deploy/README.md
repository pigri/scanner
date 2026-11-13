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

## VPN egress namespaces (REQUIRED — the workers fail closed without them)

The scan workers egress through WireGuard network namespaces so scan traffic
never leaves the host IP, and the fleet is split by target country (commit
"Split scan-worker fleet by target country"):

| Worker unit            | netns        | Claims                      | Egress        |
| ---------------------- | ------------ | --------------------------- | ------------- |
| `scan-worker@`         | `scanvpn`    | everything **except** `.hu` | Windscribe    |
| `scan-worker-hu@`      | `scanvpn-hu` | **only** `.gov.hu` / `.hu`  | WireGuard, HU exit |

Each worker's `ExecStartPre` **fails closed** (refuses to start) until its netns
exists, so the netns units below are a hard prerequisite. If `scanvpn-hu` is
missing, `scan-worker-hu@` hangs forever in `start-pre` and every `.hu` target
sits unclaimed in `scan_queue` — no new findings, and the UI News page shows
nothing new.

These are **system** units (netns creation needs root), installed outside the
repo tree:

```bash
# Foreign egress namespace (scanvpn) — needs /etc/wireguard/scanvpn.conf present
sudo install -m 0755 scanvpn-netns.sh /usr/local/sbin/scanvpn-netns.sh
sudo install -m 0644 scanvpn-netns.service /etc/systemd/system/scanvpn-netns.service

# HU egress namespace (scanvpn-hu) — needs /etc/wireguard/scanvpn-hu.conf present
sudo install -m 0755 scanvpn-netns-hu.sh /usr/local/sbin/scanvpn-netns-hu.sh
sudo install -m 0644 scanvpn-netns-hu.service /etc/systemd/system/scanvpn-netns-hu.service

sudo systemctl daemon-reload
sudo systemctl enable --now scanvpn-netns.service scanvpn-netns-hu.service

# verify: each namespace exists and routes default via its wg interface
ip netns list | grep -E 'scanvpn($| )|scanvpn-hu'
sudo ip netns exec scanvpn    ip route
sudo ip netns exec scanvpn-hu ip route
# the stuck workers clear start-pre on their own (Restart=on-failure loop):
systemctl --user is-active scan-worker@1 scan-worker@2 scan-worker-hu@1 scan-worker-hu@2
```

Both scripts read the tunnel's address(es) and DNS straight from their
`/etc/wireguard/scanvpn{,-hu}.conf`, so rotating a key or switching the WireGuard
provider means replacing only that file and restarting the matching
`scanvpn-netns{,-hu}` unit — no edit to the script. Re-add the
`PersistentKeepalive = 25` line to the new conf (many provider exports drop it);
see the troubleshooting note below for why.

If the conf carries an IPv6 `Address`, `up()` also installs an IPv6 default route
through the tunnel. Keep IPv6 only when the exit really routes IPv6 to the
internet; otherwise remove the IPv6 entries from `Address` and `DNS`, so IPv6
fails at once with "network unreachable" and tools fall back to IPv4.

The netns units are **system** units but the workers are **user** units, and a
worker joins its namespace only when it starts. Restarting `scanvpn-netns{,-hu}`
replaces the namespace, so a running worker would keep working in the old,
deleted one. Each worker is started with `--netns <name>` and checks before every
claim that it is still in `/run/netns/<name>`. On a mismatch it claims nothing and
exits with status 75; `Restart=on-failure` then starts it again inside the current
namespace, after the `ExecStartPre` wait. The same check resolves a probe name
(`--dns-probe`, default `example.com`). When DNS fails the worker pauses claiming
and retries with a backoff from `--poll-interval` up to 5 minutes, then carries on
by itself. The probe queries the nameservers in the namespace's `resolv.conf`
directly, not through nsswitch, so a host-side resolver cannot answer it.

The namespace (not DNS) is checked again after each batch, before its rows are
marked. If it changed while the batch ran, or cannot be checked, the rows this
worker still owns return to the queue without counting an attempt, and the worker
exits with status 75. Whatever that batch already wrote (its run, findings and
risk rows) stays in the database until the targets are scanned again.

Fallback: a worker started without `--netns` has no such check. After restarting
`scanvpn-netns{,-hu}`, restart the matching workers by hand
(`systemctl --user restart scan-worker-hu@1 scan-worker-hu@2`).
`sudo ip netns pids scanvpn-hu` lists the processes in the current namespace.

### Troubleshooting: tunnel comes up but never handshakes

If `sudo ip netns exec scanvpn-hu wg show wgscan-hu` shows **no "latest
handshake" and 0 B received** (handshake init sent, nothing back) while ordinary
TCP egress still works, the cause is almost always the **host firewall dropping
the UDP return traffic**, not a bad key or a down server.

WireGuard is **UDP-only**, and the host's stateless firewall (Hetzner Robot)
does not auto-allow return packets: outbound "allow all" lets the handshake
*init* leave, and TCP replies get back in via the usual `tcp established`
(dport 32768-65535, flag `ack`) rule — but there is **no UDP equivalent**, so the
server's reply (UDP, **source port = the endpoint's port** from the conf's
`Endpoint`, e.g. `443` for Windscribe or `51820` for a stock WireGuard server)
hits the default `discard`. Fix is an **incoming** rule: `udp`, that source port,
action `accept` (match on source port — the host's WG listen port is random per
restart). Commit that rule into
whatever manages the firewall, or the next apply silently re-breaks every tunnel.

On a self-hosted WireGuard server, a newly created peer can also show this
pattern: the exported conf works only once the server has applied the new peer.
Until then the server ignores its handshakes, while existing peers keep working.
Capture on the host uplink (`tcpdump -ni <uplink> udp and host <endpoint-ip>`) to
tell the cases apart: replies arriving there but not in `wg show` point at the host
firewall; no replies at all point at the server or an upstream filter.

Both `scanvpn-netns.service` and `scanvpn-netns-hu.service` now **fail closed on
a dead tunnel**: their `ExecStartPost` (`scanvpn-netns{,-hu}.sh check`) provokes a
handshake and verifies it; if none appears the check tears the netns down itself
and fails the unit (its `ExecStopPost=down` is the backstop — `ExecStop=` would be
skipped on a start that never reached "active"), so the matching worker's
netns-presence guard keeps the workers out and a present-but-dead tunnel can no
longer drain the queue into empty `done`s.

This matters beyond the scan workers: each namespace's **only resolver is the
in-tunnel DNS** (the `.conf`'s `DNS=`, reachable only through the wg interface), so
a present-but-dead tunnel also makes every in-namespace lookup fail "Could not
resolve host" — which silently freezes the CT mirror (`ct-mirror.service`) and the
daily recon refresh (`scan-feed`) with no systemd-level error. Failing the netns
unit closed is what surfaces that instead of letting it rot unnoticed.

Set `PersistentKeepalive = 25` in **both** `scanvpn.conf` and `scanvpn-hu.conf` —
treat it as a required default, not an optional extra. Provider `.conf`
exports often omit it, so it has to be re-added by hand after every key rotation; a conf
that is missing it comes up fine but then lets an idle tunnel's handshake age out,
forcing the netns `check` to re-trigger one on each start. With it, the tunnel
self-maintains the handshake and the check just confirms it. `up()` loads the
value straight from the conf via `wg setconf`, so restarting the matching
`scanvpn-netns{,-hu}` unit after adding the line is all it takes to apply it.

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

With the workers running as daemons, five **systemd timers** feed them:

- **`nvd-sync.timer`** (daily 01:30): `nvd-sync` incrementally refreshes the
  offline NVD mirror `/storage/gen0sec-scan/nvd.db` (full build when the db does
  not exist yet) that `version-match` reads during `scan-all`. Runs before the
  template refresh and `scan-feed` so the day's scans see a fresh mirror.
  `NVD_API_KEY` is read from `.env.scan`. The first build is a full pull
  (~100 min keyed, longer unauthenticated); the timer allows 4 h for it, but on
  a slow link you can bootstrap it once by hand before enabling the timer:
  `cd ~/gen0sec/redteam/scan && set -a && . .env.scan && set +a && npm run nvd-sync -- --full --nvd-db /storage/gen0sec-scan/nvd.db`.
- **`version-match-sweep.timer`** (daily 02:00, after `nvd-sync`): `version-match
  --all` re-matches the version evidence already in `scan.db` (http_probes /
  ports seen in the last 30 days) against the fresh mirror, so CVEs published
  since a host was last scanned appear without a rescan, then runs `cve-rollup`.
  It does this once per `nvd.db` snapshot: a second firing on the same snapshot
  exits 0 without writing. A missing `nvd.db` warns and exits 0. The marker is a
  `runs` row (`tool='version-match-sweep'`, `args_json.snapshotAt`). If the
  rollup fails the unit fails, and the next firing retries only the rollup.
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
         nuclei-update-templates.service nuclei-update-templates.timer \
         nvd-sync.service nvd-sync.timer \
         version-match-sweep.service version-match-sweep.timer; do
  ln -sf ~/gen0sec/redteam/scan/deploy/$u ~/.config/systemd/user/$u
done
systemctl --user daemon-reload
systemctl --user enable --now scan-feed.timer scan-rescan.timer nuclei-update-templates.timer nvd-sync.timer \
  version-match-sweep.timer

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
- Interrupted batches leave their rows `in_progress`; the workers return them to
  `pending` by themselves (see the queue section of the top-level README).
- `ExecStart` sources `~/.nvm/nvm.sh` explicitly so nvm-managed node/npx resolve
  under systemd's clean environment (a login shell alone does not, because nvm
  lives in `~/.bashrc`). If you use a system node instead, replace the
  `export NVM_DIR=...; . nvm.sh;` prefix with the absolute `npx` path.
- `ExecStart` also sources `.env.scan` (from the scan dir) if present, so
  `WPSCAN_API_TOKEN` and any other per-operator secrets reach the wpscan child
  without being baked into the unit. See `.env.scan.example` for the template.
