# discovery

Passive recon toolkit for enumerating hosts under a target domain suffix. TypeScript, Vitest-tested pure logic, thin CLI wrappers around DNS / HTTP / CT-log sources.

Built for the `.gov.hu` engagement but generalizes to any suffix. From a single `site:target` starting point, the pipeline expands to hundreds or thousands of forward-verified hosts.

## Layout

```
discovery/
  src/
    lib/            pure, tested
      ddg.ts        decodeDdgUrl, hostOf, makeDomainFilter
      graph.ts      buildGraph, EnrichedRow types
      asn.ts        normalizeAsn, extractPrefixes, dedupePrefixes, familyOf
      ct.ts         extractCtHosts, extractCertspotterHosts, expandNameValue
      ptr.ts        expandCidr, cidrSize, extractHostsFromResults
    ddg-sweep.ts    stage 1 — Puppeteer DDG sweep
    enrich.ts       DNS/PTR/ASN/country lookup, JSONL + CSV out
    visualize.ts    self-contained HTML dashboard with findings table + network
    asn-prefixes.ts RIPE Stat / bgpview.io ASN → announced CIDRs
    ct-log.ts       crt.sh + Certspotter certificate transparency
    ptr-sweep.ts    walk a CIDR list, reverse-DNS every IP
    dns-brute.ts    SecLists wordlist × parent list, dig-based
    refresh.ts      orchestrator: ct-log → dns-brute → enrich → filter
  test/             38 tests (ddg, graph, asn, ct, ptr)
  parents.txt       seed parent list for refresh / dns-brute
  prefixes.txt      seed CIDR list for ptr-sweep
  sweep.sh          convenience runner for the DDG sweep
  install-windscribe.sh
  package.json      npm run <script> per tool
  tsconfig.json     strict (noUncheckedIndexedAccess, exactOptionalPropertyTypes)
```

## Setup

```
npm install
npm test            # 38 tests, ~200ms
npm run typecheck   # tsc --noEmit
```

External tools used at runtime: `dig` (bind9-dnsutils), optional `windscribe-cli` for IP rotation in the DDG sweep (see below). Node 20+ required.

### IP rotation (Windscribe)

DuckDuckGo rate-limits per-IP; the sweep hits an "anomaly" page after ~15–25 productive pages from the same IP. With `windscribe-cli ip rotate` wired in, each anomaly rotates the exit IP instead of waiting through a 90s cooldown, which lets the sweep run continuously and roughly doubles the yield per hour.

**Install (Debian/Ubuntu):**
```
./install-windscribe.sh   # downloads the right .deb for your arch, runs sudo apt install
```

**One-time login:**
```
windscribe-cli login              # interactive: username + password
windscribe-cli connect best       # pick a server (or 'Toronto', 'CA', etc.)
windscribe-cli status             # verify state + current IP
```

**Wire into the sweep:**
```
npm run sweep -- 'site:.target.tld' --suffix .target.tld --windscribe
# equivalent to: --rotate-cmd 'windscribe-cli ip rotate'
```

Or via `sweep.sh` (env var `ROTATE` — set to empty to disable):
```
ROTATE='windscribe-cli ip rotate' ./sweep.sh
```

**Behavior on rate-limit:**
1. Anomaly page detected → `--rotate-cmd` invoked.
2. Egress IP verified via `--rotate-verify-url` (default `https://api.ipify.org?format=text`) before and after — if the IP didn't change (Windscribe sometimes reconnects to the same server), falls back to the `--cooldown-ms` sleep.
3. On rotate success, sweep resumes immediately with a fresh cookie jar.

**Other providers:** `--rotate-cmd` accepts any shell command. Examples:
- Mullvad: `--rotate-cmd 'mullvad reconnect'`
- Tailscale exit-node cycle: `--rotate-cmd 'tailscale set --exit-node=$(shuf -n1 -e node-a node-b node-c)'`
- Tor: `--rotate-cmd "printf 'AUTHENTICATE\nSIGNAL NEWNYM\n' | nc 127.0.0.1 9051"`

## Tools

Every wrapper is invocable as `npm run <name> -- <args>` or `npx tsx src/<name>.ts <args>`.

### subfinder / amass / fierce / dnsenum / theharvester

External-tool wrappers, all write into `recon.db` (source tag = tool name), all accept `--suffix` + `--merge`.

```
npm run subfinder    -- gov.hu --sqlite recon.db --suffix gov.hu --merge domains.txt
npm run amass        -- gov.hu --sqlite recon.db --suffix gov.hu -- -active -brute
npm run fierce       -- gov.hu --sqlite recon.db --suffix gov.hu
npm run dnsenum      -- gov.hu --sqlite recon.db --suffix gov.hu
npm run theharvester -- gov.hu --sqlite recon.db --suffix gov.hu --sources crtsh,duckduckgo,hackertarget
```

Install with `./install-tools.sh` (apt: `fierce dnsenum theharvester`; Go install: `subfinder amass`).

### ddg-sweep

Puppeteer sweep of `lite.duckduckgo.com/lite/` across query variants × region rotations. Discovers indexed subdomains. Rotates the exit IP via a supplied shell command on rate-limit.

```
npm run sweep -- 'site:.gov.hu' \
  --terms 'kormány,minisztérium,önkormányzat,2024,2025' \
  --regions wt-wt,hu-hu,us-en,de-de \
  --suffix .gov.hu --exclude nki.gov.hu,nbsz.gov.hu \
  --out domains.txt --windscribe
```

Key flags: `--terms`, `--regions`, `--suffix`, `--exclude`, `--max-pages`, `--delay-ms`, `--rotate-cmd`, `--windscribe`, `--rotate-verify-url`.

### ct-log

Query certificate transparency logs (crt.sh + Certspotter, union). Handles wildcard-cert masking. crt.sh 502s frequently → falls back to Certspotter automatically.

```
npm run ct-log -- 'hosting.gov.hu' --suffix gov.hu --merge domains.txt \
  --source both -o hosting-ct.txt
```

Key flags: `--source crtsh|certspotter|both`, `--suffix`, `--exclude`, `--merge`.

### enrich

For each hostname: A/AAAA lookup, PTR, ipinfo MMDB (ASN, org, country, continent). Emits per-domain JSONL and per-(domain, ip) CSV. Auto-downloads the MMDB on first run.

```
npm run enrich -- domains.txt --concurrency 40
```

Key flags: `--concurrency`, `--timeout-ms`, `--resolvers`, `--no-ipv6`, `--no-ptr`, `--refresh-mmdb`, `--out-jsonl`, `--out-csv`.

**Gotcha:** don't pass `--resolvers 1.1.1.1,...` unless outbound :53 to public IPs works from this host. Default (system resolver via systemd-resolved) is more reliable.

### visualize

Reads `enriched.jsonl` and emits a self-contained `graph.html` dashboard with:
- **Findings** table (default) — sortable, filterable by ASN/country, search across domain/IP/PTR/ASN/org, "PTR differs from domain" toggle, "shared IPs only" toggle.
- **Network** graph — vis-network force layout. Search hides non-matches and keeps 1-hop neighbors.
- **ASN distribution** bar charts.
- **Country** breakdown.
- **Shared IPs** table.

```
npm run visualize -- enriched.jsonl -o graph.html --title 'target recon'
```

### asn-prefixes

Fetch announced CIDR ranges for one or more ASNs. RIPE Stat by default; `--source bgpview` alt. Dedupes across ASNs, sorts by IP within family.

```
npm run asn-prefixes -- 1955 31581 -o prefixes.txt --out-json prefixes.json
```

### ripe-search

Reverse of `asn-prefixes`: search the RIPE database by free-text (name /
descr / netname / org-name) and emit matching CIDRs, ASNs, and org handles.
Use it to seed a prefix list from an organisation, ministry, or provider
name rather than a known ASN. Post-filters by country (default: HU); the
`inetnum` range attribute is decomposed into maximal CIDR blocks.

```
npm run ripe-search -- kormany "gov.hu" NISZ KIFÜ "Nemzeti Infokommunikáció" \
  -o hu-gov-prefixes.txt --out-asns hu-gov-asns.txt --out-json hu-gov.json
```

Chain the ASN output into `asn-prefixes` for full BGP-announced expansion
(the RIPE inetnum objects only cover what's registered — an ASN often
announces more):

```
npm run asn-prefixes -- $(cat hu-gov-asns.txt) -o hu-gov-bgp-prefixes.txt
```

Then feed the CIDR list into the existing pipeline (`ptr-sweep`, `masscan`,
etc.). `--no-country` disables the geo filter for orgs registered abroad
that still operate HU infrastructure.

### ct-mirror

Local Certificate Transparency mirror driven by [`scrape-ct-log`][scl]. Polls
one or more CT log shards forward-only from a baseline `tree_size`, parses
each entry's DER cert (`node:crypto.X509Certificate`), extracts SAN + CN
DNS names, filters against `scope.txt`, stores scope-matched
`(entry, name)` pairs in `ct.db`, and enqueues newly-observed hosts into
`scan.db`'s `scan_queue`. Bypasses crt.sh / certspotter rate limits by
talking to CT log servers directly over the public CT protocol.

[scl]: https://github.com/mpalmer/scrape-ct-log

Install `scrape-ct-log` (Rust; no cargo-install yet, build from source):

```
git clone --depth=1 https://github.com/mpalmer/scrape-ct-log.git ~/scrape-ct-log
cd ~/scrape-ct-log && cargo build --release
ln -sfv $PWD/target/release/scrape-ct-log ~/.local/bin/scrape-ct-log
```

Seed the shards you want to mirror (Argon 2026h1 + Nimbus 2026 covers most
CAs — every prod cert lands in at least two logs):

```
npm run ct-mirror -- init argon2026h1 https://ct.googleapis.com/logs/us1/argon2026h1/
npm run ct-mirror -- init nimbus2026  https://ct.cloudflare.com/logs/nimbus2026/
npm run ct-mirror -- shards
```

Pull the delta on demand (or via the systemd timer — see below):

```
npm run ct-mirror -- update            # for every registered shard
npm run ct-mirror -- query --suffix nisz.hu
npm run ct-mirror -- query --since "$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)"
```

Systemd wiring — 30-min timer inside the `scanvpn` netns, unit files live
in `../scan/deploy/`:

```
ln -sfv $PWD/../scan/deploy/ct-mirror.service ~/.config/systemd/user/
ln -sfv $PWD/../scan/deploy/ct-mirror.timer   ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now ct-mirror.timer
```

Env overrides: `CT_DB` (default `ct.db`), `SCAN_DB` (default
`../scan/scan.db`), `SCOPE_TXT` (default `../scan/scope.txt`), `SCRAPE_BIN`
(default `scrape-ct-log` on PATH), `CT_MAX_ENTRIES` (per-shard per-update
cap, default 500 000 — safety net so a stalled worker doesn't try to pull
weeks of backlog in one shot).

Full cert bodies are NOT stored — only their SHA-256 fingerprint for audit +
dedup. Wildcard SANs (`*.zone.hu`) match scope suffixes but are NOT enqueued
(a wildcard isn't a resolvable host on its own; use `dns-brute` to find
subdomains under the parent zone).

### ptr-sweep

Walks a CIDR list and reverse-DNSes every IPv4 via node's dns module. Fast when the local stub can keep up.

```
npm run ptr-sweep -- prefixes.txt --suffix gov.hu -o ptr-hosts.txt --concurrency 100
```

**Reliability caveat:** systemd-resolved drops responses at high concurrency. For bulk PTR work, prefer `xargs -P N | dig @1.1.1.1` (see recipes below) which handles >1000 QPS reliably.

### dns-brute

Forward-DNS brute against `<word>.<parent>` for every parent × word. Auto-fetches SecLists wordlists on first run; caches to `./wordlists/`.

```
npm run dns-brute -- --parents parents.txt --seclist top-5000 \
  --merge domains.txt -o brute-hosts.txt
```

Wildcards detected per-parent — matches against a wildcard's IPs are excluded so bogus expansions don't slip in.

Wordlist names: `top-5000`, `top-20000`, `top-110000`, `bitquark-100k` (SecLists).

Key flags: `--parents`, `--seclist`, `--wordlist` (local path override), `--resolver` (default `1.1.1.1`), `--concurrency`, `--no-wildcard`.

### db-init

Initialize / open a SQLite backing store (schema at `src/lib/schema.sql`). Optionally backfill from an existing `enriched.jsonl`.

```
npm run db-init -- --db recon.db --from-jsonl enriched.jsonl --timestamp 2026-08-18T12:00:00Z
```

Every other tool accepts `--sqlite recon.db` and writes hosts / IPs / resolutions / PTR history / run log into it. Multiple runs over time build a full timeline — the same host / IP can appear many times with different `seen_at` timestamps, so you can query "what changed between date A and date B".

### query

Read-only queries against the DB, including date-range filters.

```
npm run query -- new --since 2026-08-15                     # hosts first_seen since date
npm run query -- new --since 2026-08-01 --until 2026-08-15  # inclusive window
npm run query -- sources                                    # distinct hosts by source tag
npm run query -- runs                                       # last 20 refresh runs
npm run query -- sql "SELECT as_name, COUNT(*) n FROM ips GROUP BY as_name ORDER BY 2 DESC LIMIT 10"
```

Or shell out with the `sqlite3` CLI for ad-hoc: `sqlite3 recon.db 'select count(*) from hosts'`.

### refresh

One-shot orchestrator: CT logs per parent → SecLists brute → enrich → phantom filter. Writes `refresh-summary.json` with a delta count for downstream reporting / cron.

```
npm run refresh -- --seclist top-5000 --ct-sources certspotter
```

Key flags: `--parents`, `--suffix`, `--domains`, `--seclist`, `--ct-sources`, `--skip-brute`, `--skip-ct`, `--skip-enrich`.

**With the SQLite store on:** pass `--sqlite recon.db` to every stage (or bake it into the refresh call) and every host / IP / PTR / resolution is stamped with a UTC timestamp. Query "what changed since yesterday" with `npm run query -- new --since 2026-08-18`. Schema at `src/lib/schema.sql`; the tables are `hosts`, `sources`, `ips`, `resolutions`, `ptr_records`, `runs`.

## Pipeline

```
[ site:target ]
      │
      ▼
   ddg-sweep ─────► domains.txt ◄──── ct-log ◄──── parents.txt
                       │  ▲
                       │  └────── dns-brute ◄────── seclists wordlist
                       │  ▲
                       │  └────── ptr-sweep ◄───── prefixes.txt ◄── asn-prefixes
                       ▼
                    enrich ─────► enriched.jsonl
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   enriched.csv   visualize        phantom filter
                       │
                       ▼
                   graph.html
```

## Common recipes

**Fresh engagement bootstrap:**
```
npm run sweep -- 'site:.target.tld' --suffix .target.tld -o domains.txt
npm run enrich -- domains.txt
npm run visualize -- enriched.jsonl -o graph.html
```

**Expand ASN address space then reverse-DNS everything:**
```
npm run asn-prefixes -- AS<N> -o prefixes.txt
seq 0 255 | awk '{print "10.0.0."$1}' \
  | xargs -P 100 -I{} bash -c 'ptr=$(dig +short -x {} @1.1.1.1); [ -n "$ptr" ] && echo "{} $ptr"'
# or with proper CIDR expansion:
python3 -c "import ipaddress,sys
for line in open(sys.argv[1]):
  for ip in ipaddress.ip_network(line.strip()): print(ip)" prefixes.txt \
  | xargs -P 100 -I{} bash -c 'ptr=$(dig +short -x {} @1.1.1.1); [ -n "$ptr" ] && echo "{}\t$ptr"'
```

**PTR pivot on enriched output:** any PTR that names a *different* in-scope host is a new lead.
```
awk -F, 'NR>1 && $4 != ""' enriched.csv | awk -F, '{print $4}' | tr '|' '\n' \
  | grep -Eio '[a-z0-9-]+(\.[a-z0-9-]+)*\.target\.tld' | sort -u > ptr-hosts.txt
sort -u domains.txt ptr-hosts.txt -o domains.txt
npm run enrich -- domains.txt
```

**Phantom filter after any merge:**
```
python3 -c "
import json
resolved, failed = [], []
for line in open('enriched.jsonl'):
    row = json.loads(line)
    (resolved if row['addresses'] else failed).append(row['domain'])
open('domains.txt', 'w').write('\n'.join(sorted(resolved)) + '\n')
open('phantoms.txt', 'w').write('\n'.join(sorted(failed)) + '\n')
"
```

**Recurring refresh (local cron):**
```
7 3 * * * cd /path/to/discovery && npm run refresh -- --seclist top-5000 --ct-sources certspotter >> refresh.log 2>&1
```

## Testing

```
npm test              # vitest run
npm run test:watch
npm run typecheck
```

TDD discipline: new pure logic goes into `src/lib/*.ts` with a red-green-refactor cycle in `test/*.test.ts`. Entry-point files (`src/*.ts`) are thin I/O wrappers around the lib and are not unit-tested.

## Gotchas

- **crt.sh 502s frequently** on wide queries. `ct-log --source both` falls back to Certspotter automatically.
- **Wildcard certs mask their subdomains** in CT logs — a `*.foo.tld` cert reveals only `foo.tld`, not the individual hosts. Use `dns-brute` or `ptr-sweep` when CT yield is low.
- **systemd-resolved drops** responses at high concurrency. For bulk PTR work use the `xargs | dig @1.1.1.1` pattern (see recipes). `ptr-sweep.ts` uses node's dns module and is fine at concurrency ≤50.
- **Node's `dns.Resolver.setServers(['1.1.1.1'])` returns EREFUSED** on hosts where outbound :53 to public IPs is firewalled. `dig @1.1.1.1` still works because it's a separate binary path. Default enrich mode uses the system resolver.
- **PTR ≠ forward-resolvable.** Always filter after merging PTR-derived hosts — most work, but 5-10% are stale / internal-only / auto-generated placeholders. See "Phantom filter" recipe.
- **Wildcard DNS on some parents** — `dns-brute` detects and excludes matching IPs automatically.
- **MMDB URL** — always `https://github.com/gen0sec/geoip-databases/releases/latest/download/ipinfo_lite.mmdb`. Never pin a dated tag; the DB is rebuilt on a rolling cadence.

## Public-repo hygiene

`.gitignore` excludes results and secrets:
- `node_modules/`, `wordlists/`
- `*.mmdb`, `sweep.log`, `sweep.stdout`, `*.png`
- `domains.txt`, `enriched.jsonl`, `enriched.csv`, `phantoms.txt`, `graph.html`
- `discovery/` (per-engagement working dirs)

Never commit target lists, results, or logs. Never include customer names, internal URLs, or engagement scope in filenames, code comments, or commit messages.
