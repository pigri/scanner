# scan

Active-scan toolkit for an authorized target set. TypeScript, Vitest-tested pure logic, thin CLI wrappers around industry tools (nmap, httpx, nuclei, wpscan, masscan, testssl.sh, gowitness, subdomain-takeover), with a shared scope gate, normalized JSONL output, and a SQLite backing store with per-tool history.

Companion to `../discovery/`. Feed it `discovery/domains.txt` or `discovery/prefixes.txt` after you have written scope authorization from the target owner.

## Scope

**Warning-only by default.** Reads an optional `scope.txt` (suffixes + CIDRs). Every target is checked and out-of-scope ones are logged as warnings; `--strict` refuses to run when any target falls out of scope.

The gate exists so stray hosts don't fan the scan onto neighbouring infrastructure. It is **not** legal authorization — the operator is responsible for having written scope from the target owner before running any of these tools.

`scope.txt` format:
```
# comments allowed
.gov.hu            # any host under gov.hu
example.com        # exact + subdomains
84.206.0.0/16      # IPv4 CIDR
2001:738::/32      # IPv6 CIDR
```

## Layout

```
scan/
  src/
    lib/
      scope.ts         # parseScope, inScope, checkTargets       (pure, tested)
      targets.ts       # parseTargets, splitTargets              (pure, tested)
      nmap-parse.ts    # parseNmapXml → JSON                     (pure, tested)
      db.ts            # openDb + typed inserts + queries        (pure, tested)
      schema.sql       # SQLite schema (WAL, ISO 8601 timestamps)
      runner.ts        # prepareTargets, run, requireTool, parseCommonCli
    nmap.ts            # nmap -Pn -sV -T3 --top-ports 1000
    httpx.ts           # httpx -sc -title -td -web-server -tech-detect
    nuclei.ts          # nuclei -severity medium,high,critical
    wpscan.ts          # wpscan per host, WPSCAN_API_TOKEN aware
    masscan.ts         # masscan -p<top9> --rate 10000 (needs sudo)
    testssl.ts         # testssl.sh --parallel --fast --sneaky
    gowitness.ts       # gowitness file -f <urls> --threads 20
    takeover.ts        # nuclei -tags takeover
    scan-all.ts        # orchestrator
    db-init.ts         # init/open the SQLite DB
    query.ts           # queries against the DB (findings, ports, runs, sql)
  test/                28 tests (scope, targets, nmap-parse, db)
  install-tools.sh     # sudo installer for the 7 external binaries
  package.json         # npm run <tool>, npm test, npm run typecheck
  tsconfig.json        # strict (noUncheckedIndexedAccess, exactOptionalPropertyTypes)
  .gitignore           # covers node_modules, *.jsonl, *.xml, screenshots/, scope.txt, *.db
```

## Setup

```
npm install
npm test               # 28 tests
npm run typecheck
./install-tools.sh     # nmap, masscan, testssl.sh, wpscan, httpx, nuclei, gowitness (sudo)
```

External binaries expected on `$PATH`:
- **nmap** (`apt install nmap`)
- **masscan** (`apt install masscan`)
- **testssl.sh** (`apt install testssl.sh`)
- **wpscan** (`gem install wpscan`)
- **httpx**, **nuclei**, **gowitness** (`go install ...`, via `install-tools.sh`)

Optional env var: `WPSCAN_API_TOKEN` unlocks CVE data in wpscan output.

## Per-run output layout

When `--sqlite scan.db` is set (and `--out` isn't), every tool writes its raw output under `runs/<run_id>/`:

```
runs/
  1/
    nmap.jsonl
    nmap.xml
    nmap-targets.txt
  2/
    httpx.jsonl
    httpx-targets.txt
  3/
    nuclei.jsonl
  4/
    wpscan.jsonl
  5/
    testssl.jsonl
    testssl-<host>.json     (kept, one per host)
  6/
    screenshots/*.png
  ...
```

Every DB row (findings/ports/http_probes/screenshots/risk_scores) has a `run_id` foreign key so you can join back to the raw file. Nothing is overwritten between runs.

Override with `--run-dir <base>` (default `runs`) or disable per-run dirs with `--no-run-dir` (falls back to cwd, legacy behavior).

### rustscan

Fast full-range TCP-connect sweep (no root, works over any egress including
VPN/WireGuard netns). Resolves FQDN targets internally; the wrapper keys ports
by target=FQDN so joins with `findings`/`http_probes` stay intact. Always runs
in `--greppable` mode (no built-in nmap handoff — the pipeline has its own
nmap stage).

```
npm run rustscan -- --targets prefixes.txt --scope scope.txt --sqlite scan.db \
  -- --ulimit 5000 --range 1-65535
```

### naabu

ProjectDiscovery's port scanner — TCP-connect by default (`-scan-type c`) so
it works over any transport including WG/tun netns where masscan can't. JSON
output natively carries both `host` (FQDN) and `ip`, so no reverse-map dance.
Kept alongside rustscan as a second connect-mode sweeper (different code
paths, different bug surface — running both catches issues either alone would
miss).

```
npm run naabu -- --targets top100.txt --scope scope.txt --sqlite scan.db \
  -- --top-ports full --rate 2000
```

### autorecon

Heavy per-target orchestrator (Tib3rius). Doesn't parse into DB — output tree is per-service. Useful for one-off deep dives.

```
npm run autorecon -- --targets short-list.txt --scope scope.txt --sqlite scan.db
```

### SMB suite (enum4linux, enum4linux-ng, smbmap, rpcclient)

All accept `--live-only` (filter to hosts with 445/139 in `ports` table).

```
npm run enum4linux-ng -- --targets top100.txt --scope scope.txt --sqlite scan.db -- --live-only
npm run smbmap        -- --targets top100.txt --scope scope.txt --sqlite scan.db -- --live-only
npm run rpcclient     -- --targets top100.txt --scope scope.txt --sqlite scan.db -- --live-only
npm run enum4linux    -- --targets top100.txt --scope scope.txt --sqlite scan.db -- --live-only
```

Findings land in `findings` table with `tool='enum4linux'|'enum4linux-ng'|'smbmap'|'rpcclient'`.

### nmap --nse and masscan --banners

Extended wrappers:
```
npm run nmap    -- --targets top100.txt --sqlite scan.db -- --nse "vuln,safe,http"
npm run masscan -- --targets prefixes.txt --sqlite scan.db -- --banners --source-ip <your-ip>
```

Masscan needs an L2 (ethernet) next-hop. Inside a WireGuard/tun-only netns
(default egress interface `wg*` / `tun*`), the wrapper auto-skips and logs
why — masscan crafts raw ethernet frames and the packets go nowhere on a
point-to-point tunnel. Run it out-of-band on the host or through an eth
egress if you need masscan coverage.

### enqueue + worker (batching queue)

Instead of manually crafting `top100.txt` / `top100-next.txt` files, populate a persistent SQLite queue and let a worker chew through it in batches.

```
npm run enqueue -- --from-risk 500                          # top-500 unscanned by risk
npm run enqueue -- --from-file ../discovery/domains.txt     # everything discovery found
npm run enqueue -- host1 host2 host3                        # ad-hoc, priority 0
npm run worker  -- --batch-size 50 --scope scope.txt        # loops until queue is empty
```

**Queue design** — SQLite-backed priority queue:

- Table `scan_queue(target UNIQUE, priority, status, queued_at, started_at, finished_at, run_id, attempts, error)`.
- Ordering: `priority DESC, id ASC` (highest priority first, FIFO tiebreak).
- Dequeue is atomic (`SELECT` + `UPDATE status='in_progress'` in one transaction) — safe if you ever run two workers, though the DB will serialise them.
- Dedup via `INSERT OR IGNORE` — re-enqueuing the same host is a no-op.
- States: `pending → in_progress → done | failed`. Failed rows retain an `error` and `attempts` count.
- **No auto-reaper for crashed `in_progress` rows** — if a worker is killed mid-scan, requeue them manually:
  ```
  sqlite3 scan.db "UPDATE scan_queue SET status='pending' WHERE status='in_progress'"
  ```

**Worker loop:**
1. `claimBatch(N)` — grab next N pending rows.
2. Write to `queue-batch-<n>.txt`.
3. `spawn npx tsx src/scan-all.ts --targets queue-batch-<n>.txt --sqlite scan.db …`.
4. Mark done (with `run_id`) or failed (with error string).
5. Repeat until queue empty or `--max-batches` reached.

**Recipes:**
```
# Score everything, enqueue top-500 highest risk not yet scanned, then chew:
npm run risk    -- --db scan.db --discovery-db ../discovery/recon.db --suffix gov.hu
npm run enqueue -- --from-risk 500
npm run worker  -- --batch-size 50 --scope scope.txt

# One-shot small batch (5 hosts) for a quick verification:
npm run enqueue -- --from-risk 5
npm run worker  -- --batch-size 5 --max-batches 1 --scope scope.txt

# Requeue everything that failed:
sqlite3 scan.db "UPDATE scan_queue SET status='pending', error=NULL WHERE status='failed'"
```

### retention

Prune old run dirs + orphan DB rows.

```
npm run retention -- --older-than 30 --keep-min 3          # dry-run
npm run retention -- --older-than 30 --keep-min 3 --apply  # delete
```

- `--older-than N` — prune runs older than N days (default: 30)
- `--keep-min N` — always keep the N newest runs *per tool* even if old (default: 3)
- `--apply` — actually delete (default is dry-run)

Deletes cascade across `findings`, `ports`, `http_probes`, `screenshots`, `risk_scores`, `runs` in one transaction, then removes the `runs/<id>/` directory. Runs without a directory (e.g. legacy) still get their DB rows pruned.

Add to cron for automatic housekeeping:
```
0 4 * * 0 cd /path/to/scan && /home/pigri/.nvm/versions/node/v26.1.0/bin/npm run retention -- --older-than 60 --keep-min 5 --apply >> retention.log 2>&1
```

## SQLite backing store

Every wrapper accepts `--sqlite scan.db` and writes structured findings alongside its normal JSONL/CSV output. Rows are ISO-8601 stamped so date-range diffs work.

```
npm run db-init -- --db scan.db            # initialize schema
npm run scan-all -- --targets ../discovery/domains.txt --scope scope.txt --sqlite scan.db
npm run query -- findings --since 2026-08-19 --severity high
```

**Schema:**
- `runs` — every tool invocation with `started_at`, `finished_at`, args_json, targets/findings counts
- `ports` — open-port observations from nmap + masscan (target, ip, port, protocol, service, product, version, tunnel, extrainfo)
- `http_probes` — httpx fingerprints (target, url, status, title, web_server, tech_json, content_length, hash)
- `findings` — cross-tool findings from nuclei / wpscan / testssl / takeover (tool, target, category, severity, title, cve, matched_at, meta_json)
- `screenshots` — gowitness output index (target, url, path)

Every table has a `seen_at TEXT` column and an index on it — cheap range queries.

## Read-only UI

A small self-contained web dashboard over `scan.db` (and `../discovery/recon.db` if present). No build step, no framework — one Node server + one HTML page, using the `better-sqlite3` dependency already installed. It is read-only: only `GET` is served, and every DB connection is wrapped so only `SELECT`/`WITH`/`PRAGMA`/`EXPLAIN` statements are allowed (`exec()` is disabled), so it cannot mutate anything even when pointed at a live, actively-written WAL DB. (Connections are opened read-write at the SQLite level *only* so SQLite can maintain the WAL `-shm` index needed to read a live database; the statement guard is what guarantees no content is written.)

```
npm run ui                                              # scan.db + ../discovery/recon.db, http://127.0.0.1:8787
npm run ui -- --sqlite /storage/gen0sec-scan/scan.db --recon-db ../discovery/recon.db --port 8787
```

Flags: `--sqlite <path>` (scan DB, default `scan.db`), `--recon-db <path>` (auto-detected at `../discovery/recon.db`), `--port` / `-p`, `--host` (default `127.0.0.1`). Env: `UI_PORT`, `UI_HOST`.

Views: **Overview** (inventory counts, severity breakdown, highest-risk targets, top ports, recent runs), **Targets** (multi-select severity facets, CVE-presence, risk-score range, sort — incl. created/updated — and name search; each row shows created/updated timestamps → per-target drill-down of ports / HTTP / findings / CVEs / certs / DNS), **Graph** (per-host subgraph + a **Global** infrastructure overview), **Findings** (de-duplicated to one row per issue with **open/resolved** status from scan history, plus multi-select severity, status, tool, category, CVE-presence, date range, sort, and target/title/CVE search — all with live facet counts), **CVEs** (each id links to NVD), **Ports** (by prevalence → hosts per port), **Recon** (hosts/IPs by country + ASN + source), **News** (new findings by day). The whole UI is read-only — only `GET` is served and every DB connection allows only SELECT-class statements. Bind `--host 0.0.0.0` only behind an SSH tunnel — the UI has no auth.

**News** is a read-only feed of *newly-discovered* findings: each finding grouped by the day it was **first** observed (`MIN(seen_at)` per `target·tool·severity·category·title`, so re-scans don't re-report it), with day-chips (per-day new counts, today highlighted), a severity filter, and target/title/CVE search — sourced entirely from `scan.db`.

**Open vs resolved.** The Findings and per-target views collapse each issue to a single logical finding and mark it **resolved** when a *later* run of the same tool on the same host stopped reporting it (its `last_seen` predates that tool's most recent scan of the host), else **open**. This is inferred from scan history — a tool that simply never re-ran a host leaves its findings **open**, so "resolved" means "confirmed gone by a later scan", not "not-yet-rechecked".

**Graph** has two scopes. *Host*: type/search a host (or click `graph ▸` on a target) for its `host → ports / tech / CVEs / DNS peers` subgraph. *Global*: an aggregated **infrastructure overview** — ASN hubs (sized by host count) and shared-IP clusters (IPs co-hosting ≥ N hosts, tunable), optionally expanded to host nodes; tap a host to drill into its subgraph. Built from `recon.db` (ASN-aware; falls back to `scan.db` host↔IP without ASN). The Graph view lazy-loads Cytoscape from a CDN, so it needs browser internet; every other view is fully self-contained.

### Docker Compose

`../docker-compose.yml` runs the UI on a dedicated lab bridge (`10.52.0.0/24`, host bridge `br-lab`, container at `10.52.0.10`):

```
cd ..            # redteam/ (where docker-compose.yml lives)
docker compose up -d --build
# open http://127.0.0.1:8787   (published on loopback; also http://10.52.0.10:8787 from this host)
docker compose logs -f ui
docker compose down
```

`scan.db` is bind-mounted from `/storage/gen0sec-scan` (read-write, so SQLite can keep the WAL index; the statement guard still blocks all writes). `recon.db` is bind-mounted read-only as a seed and copied to a writable path inside the container at start (a WAL DB needs a writable directory for its `-shm`). The port is published on `127.0.0.1` only — reach it at `http://127.0.0.1:8787` (note the port; a bare host/IP hits port 80 and won't load). `10.52.0.10` is routable only from this host; use an SSH tunnel for remote access.

## Tools

Every wrapper is invoked as `npm run <name> -- <args>` or `npx tsx src/<name>.ts <args>`.

### Common flags (shared runner)

```
--targets <file>       one host/IP/URL per line
--scope <file>         suffix + CIDR allowlist (warning-only by default)
--strict               refuse to run when any target is out of scope (exit 2)
--sqlite <path>        also persist findings/ports/probes to this DB
-o, --out <file>       output file (default per-tool)
--                     everything after is passed to the underlying binary
```

### nmap

```
npm run nmap -- --targets hosts.txt --scope scope.txt --sqlite scan.db -- --top-ports 5000
```
Runs `nmap -Pn -sV -T3 --top-ports 1000 -iL <targets> -oX nmap.xml`. Parses XML → `nmap.jsonl`. Inserts open ports into `ports` table.

### httpx

```
npm run httpx -- --targets hosts.txt --scope scope.txt --sqlite scan.db
```
Runs `httpx -sc -title -td -web-server -tech-detect -follow-redirects -threads 50 -json`. Rows into `http_probes`.

### nuclei

```
npm run nuclei -- --targets hosts.txt --scope scope.txt --sqlite scan.db -- -severity critical
```
Runs `nuclei -jsonl -severity medium,high,critical -rate-limit 150 -stats`. Rows into `findings` (tool='nuclei').

Update templates weekly: `nuclei -update-templates`.

### wpscan

```
npm run wpscan -- --targets wp-hosts.txt --scope scope.txt --sqlite scan.db
```
Runs `wpscan` per URL. Emits per-host JSON to `wpscan.jsonl`. Parses `interesting_findings`, `version.vulnerabilities`, and each plugin's vulnerabilities into `findings` (tool='wpscan', category='core-vulnerability'/'plugin-vulnerability'/'interesting').

Set `WPSCAN_API_TOKEN` (from wpscan.com) for CVE lookups.

### masscan

```
npm run masscan -- --targets prefixes.txt --scope scope.txt --sqlite scan.db
```
Runs `sudo masscan -p22,80,443,3306,5432,6379,8080,8443,9200 --rate 10000 -oJ masscan.jsonl`. Rows into `ports`.

**Needs sudo/CAP_NET_RAW.**

### testssl.sh

```
npm run testssl -- --targets hosts.txt --scope scope.txt --sqlite scan.db
```
Runs `testssl.sh --parallel --fast --quiet --sneaky --warnings=off --jsonfile <per-host>` for each target. Concatenates into `testssl.jsonl`. Findings with severity LOW/MEDIUM/HIGH/CRITICAL go into `findings` (tool='testssl').

### gowitness

```
npm run gowitness -- --targets hosts.txt --scope scope.txt --sqlite scan.db
```
Screenshots every http+https URL, dropping images into `./screenshots/`. Indexes them into the `screenshots` table.

### takeover

```
npm run takeover -- --targets hosts.txt --scope scope.txt --sqlite scan.db
```
Runs `nuclei -tags takeover -rate-limit 100`. Cheap subdomain-takeover check. Findings into `findings` (tool='takeover').

### scan-all

```
npm run scan-all -- --targets hosts.txt --scope scope.txt --sqlite scan.db
```
Orchestrates the full pipeline in order: **httpx → nmap → nuclei → takeover → testssl → wpscan (only WordPress hosts from httpx) → gowitness.**

Skip stages with `SKIP=<name,name>`:
```
SKIP=wpscan,testssl npm run scan-all -- ...
```

`--sqlite` flows down to every stage automatically.

### db-init

```
npm run db-init -- --db scan.db
```
Idempotent — creates the schema if missing, otherwise no-op.

### risk

Compute a per-target threat risk score (0–100) from findings + ports + hostname patterns + (optional) discovery signals. Stores every score row with a timestamp so trends are queryable.

```
npm run risk -- --db scan.db --suffix gov.hu --discovery-db ../discovery/recon.db --top 25 --breakdown
```

**Scoring model (per target, capped at 100):**

| Signal | Weight | Cap |
|---|---:|---:|
| Critical findings | +40 each | 3 (max 120→cap) |
| High findings | +25 each | 3 |
| Medium findings | +8 each | 5 |
| Known CVE | +10 each | 3 |
| Subdomain takeover | +30 | flat |
| Weak TLS (testssl LOW/MED/HIGH/CRITICAL) | +12 | flat |
| WordPress detected | +5 | flat |
| Open port count | +2 each | 10 |
| Risk-keyword hostname (`admin`, `dev`, `staging`, `test`, `backup`, `old`, `legacy`, `jenkins`, `gitlab`, `sonar`, `phpmyadmin`, `.git`) | +8 each | 3 |
| Foreign-country host (vs `--suffix`'s expected country) | +6 | flat |
| Shared IP with >5 domains | +4 | flat |
| First-seen < 7 days ago | +3 | flat |

All logic is in `src/lib/risk.ts` (16 tests). Model is a starting point — bump/rebalance weights for your engagement style.

**With `--breakdown`:**
```
100  admin.dev.foo.gov.hu  [crit=1 high=2 tls-weak ports=5 kw=admin,dev]
 55  stale.foo.gov.hu      [high=1 takeover]
 40  blog.foo.gov.hu       [high=1 wordpress]
```

Every run stamps `risk_scores.computed_at` so you can diff between two scans:
```
npm run query -- risk --since 2026-08-19        # latest per target since date
```

### query

Read-only queries against the DB, including date filters.

```
npm run query -- findings --since 2026-08-19 --severity critical
npm run query -- findings --tool nuclei --severity high --since 2026-08-01 --until 2026-08-15
npm run query -- ports --since 2026-08-19
npm run query -- severity                          # aggregate counts
npm run query -- runs                              # last 20 runs
npm run query -- risk --since 2026-08-19           # latest risk scores per target since date
npm run query -- sql "SELECT target, COUNT(*) FROM findings WHERE severity IN ('high','critical') GROUP BY target ORDER BY 2 DESC LIMIT 20"
```

Date args accept `YYYY-MM-DD` (auto-expanded) or full ISO strings.

### resolved

Per-host regression detector: which findings stopped surfacing on the latest
scan? A finding's identity is `(tool, category, title)`. The scan window comes
from `scan_queue.{started_at, finished_at}` — same source `deep-audit` uses to
decide "have we actually scanned this host?". Hosts without a completed
`scan_queue` row are skipped.

Buckets per target:
- **resolved** — key seen before the window, absent from it
- **persistent** — key seen in both (still open)
- **novel** — key seen only in the window (new since last scan)

```
npm run resolved                                  # clean-now cohort (hosts that
                                                  # had crit/high/med/low findings
                                                  # before their last scan, none in it)
npm run resolved -- --target host.example.com     # itemize resolved / persistent / novel
npm run resolved -- --all-fixed --limit 200       # every presumed-resolved finding
npm run resolved -- --json                        # JSONL for pipelines
npm run resolved -- --include-info                # count info-severity too (default: off)
```

A finding may "disappear" because its detection template was removed
upstream — treat output as presumed-resolved, not audited-resolved. Pair
with `deep-audit` to force a wider re-scan of the clean-now cohort before
signing off.

### history

Per-finding history for one target. Groups findings by `(tool, category,
title)` and marks presence in every completed scan window (chronological).
Windows are per-tool (pulled from the `runs` table); a nuclei key's
presence in a testssl-only window renders as `-` (n/a), not `·` (absent),
so a tool that didn't run in a window doesn't count as flapping.

Grid mode — one line per key with a ✓/·/- attendance strip:

```
npm run history -- --target cca.hiteles.gov.hu --limit 15
```

Sample:
```
STATUS      12345678901234567  SEV      TOOL       KEY
resolved    -✓-----✓-·-·-----  low      testssl    HSTS::HSTS: not offered
persistent  --✓---✓-✓✓----✓--  info     nuclei     waf-detect::WAF Detection
```

Detail mode — full per-window attendance + every observation with
`matched_at`, `run_id`, severity:

```
npm run history -- --target cca.hiteles.gov.hu --tool testssl --title "HSTS: not offered"
```

Status: `persistent` (present in latest applicable scan) / `resolved`
(absent) / `unknown` (no applicable window). A trailing `!` means ≥ 2
present↔absent transitions across applicable windows — usually WAF /
rate-limit / DNS churn, not a real fix. JSONL via `--json`.

## Pipeline

```
../discovery/domains.txt   ─┐
../discovery/prefixes.txt  ─┤
                            ▼
                        scope.txt (allowlist gate)
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
           masscan                     httpx  ────► http_probes
              │                           │
              ▼                           ▼
            ports    ◄──── nmap  ◄────────┤
              │                           │
              └───────► SCAN.DB ◄─────────┤
                         │                │
                         ▼                ▼
                    findings  ◄────  nuclei / wpscan (WP only) / testssl / takeover
                         │
                         ▼
                     query.ts / graph.html (via ../discovery/visualize --sqlite scan.db later)
```

## Testing

```
npm test              # 28 tests
npm run test:watch
npm run typecheck
```

TDD discipline: new pure logic goes into `src/lib/*.ts` with a red-green-refactor cycle in `test/*.test.ts`. Entry-point files (`src/<tool>.ts`) are thin spawn wrappers around the lib and external binaries; they are not unit-tested.

## Common recipes

**Full first-time scan into fresh DB:**
```
npm run db-init -- --db scan.db
npm run scan-all -- --targets ../discovery/domains.txt --scope scope.txt --sqlite scan.db
npm run query -- severity --db scan.db
```

**Just the critical findings from today:**
```
npm run query -- findings --db scan.db --severity critical --since $(date -Iseconds -d 'today')
```

**Delta between two scan dates:**
```
npm run query -- findings --db scan.db --since 2026-08-19 --until 2026-08-20
```

**Recurring scan (local cron):**
```
7 4 * * * cd /path/to/scan && /home/pigri/.nvm/versions/node/v26.1.0/bin/npm run scan-all -- --targets ../discovery/domains.txt --scope scope.txt --sqlite scan.db >> scan.log 2>&1
```

## Gotchas

- **Per-run output is default when `--sqlite` is set.** Files land in `runs/<run_id>/`. Add `--no-run-dir` for legacy cwd behavior. Explicit `--out <path>` always wins.
- **`runs/` grows unbounded** — schedule `npm run retention -- --older-than 60 --keep-min 5 --apply` weekly.
- **Scope gate is warning-only by default.** Not a legal safeguard. Get written authorization; use `--strict` in shared CI to enforce mechanically.
- **Rate limits.** nuclei/httpx `-rate-limit`/`-threads` are per-instance. Scanning hundreds of hosts too fast trips WAFs and gets you banned. Defaults are conservative; bump only for infra you own.
- **Nuclei templates go stale.** Run `nuclei -update-templates` before every engagement.
- **wpscan needs a real hostname/URL**, not an IP. Non-WordPress hosts return "not a WordPress site" and count against your API quota.
- **masscan requires CAP_NET_RAW / sudo.** The wrapper prepends `sudo`.
- **testssl.sh is single-host, single-shot.** For >100 hosts, split into batches or run overnight.
- **gowitness names files by URL host+port.** The screenshot index stores the filename as `target`; if you need the full URL, cross-reference `http_probes` on the same `scan.db`.
- **SQLite WAL files.** `scan.db-wal` and `scan.db-shm` appear alongside `scan.db` during writes. Ship all three (or run a checkpoint: `sqlite3 scan.db 'PRAGMA wal_checkpoint(TRUNCATE)'`).

## Public-repo hygiene

`.gitignore` excludes: `node_modules/`, `screenshots/`, `*.jsonl`, `*.xml`, `*-targets.txt`, `scope.txt`, `*.db`, `*.db-wal`, `*.db-shm`.

Never commit target lists, results, screenshots, DBs, or `scope.txt`. Never include customer names, internal URLs, or engagement scope in filenames, code comments, or commit messages.
