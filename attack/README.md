# attack

Authenticated / exploitation tools. **Not recon.** Two wrappers:

- **NetExec** (formerly CrackMapExec) — SMB/WinRM/LDAP/MSSQL/RDP/SSH/FTP execution framework
- **Responder** — LLMNR/NBT-NS/MDNS poisoner + relay listener

Sits alongside `../scan/` (recon) and `../discovery/` (passive) as a separate workspace because the legal handling, retention, and blast radius of "attack attempts" is materially different from "we probed a port".

## Non-negotiable gate

Every tool in this workspace enforces both:

1. `--scope <file>` — suffix + CIDR allowlist. Refuses to run without one.
2. `--yes-i-am-authorized` — explicit assertion that you have written authorization for every target in scope. Refuses to run without it.

There is no legacy / warning-only mode. A misfire here is a felony in most jurisdictions' computer-misuse statutes; the gate is designed to be irritating on purpose.

Out-of-scope targets → hard exit (code 4). Empty scope → hard exit. Missing `--yes-i-am-authorized` → hard exit.

## Layout

```
attack/
  src/
    lib/
      db.ts          openDb + attempt/credential/session helpers
      schema.sql     runs · attempts · credentials · sessions
      gate.ts        enforceGate() — scope + authorization check
    netexec.ts       framework wrapper
    responder.ts     poisoner wrapper
    db-init.ts       init attack.db
    query.ts         attempts / credentials / sessions / runs
  install-tools.sh   apt + pipx install
  package.json
  tsconfig.json
```

## Setup

```
npm install
./install-tools.sh   # sudo: apt install responder + pipx install NetExec
npm run db-init      # create attack.db schema
```

Write `scope.txt`:
```
# Only what you have written authorization to touch.
.example-target.tld
10.20.30.0/24
```

## netexec

```
npm run netexec -- --scope scope.txt --yes-i-am-authorized --sqlite attack.db \
  --targets smb-hosts.txt \
  -- smb smb-hosts.txt -u admin -p 'P@ssw0rd' --continue-on-success
```

- `--targets` is a hostname list used by our scope gate (netexec itself takes its own target list via its own argv after `--`).
- Attempts parsed into the `attempts` table: `target, protocol, username, password, outcome, privilege, raw_line`.
- Successful attempts with a privilege flag (`Pwn3d!`, `(admin)`) also open a `sessions` row.

## responder

```
sudo npm run responder -- --scope scope.txt --yes-i-am-authorized -I eth0 --sqlite attack.db
```

- Runs foreground; Ctrl-C to stop.
- On exit, walks `/usr/share/responder/logs/` for `NTLMv2-*.txt` / `SMB-*.txt` created since start and stores them in `credentials`.
- **LAN-only** — only intercepts LLMNR/NBT-NS/MDNS on the broadcast domain you're on. Useless for external targets.

## query

```
npm run query -- attempts       # last 50 attempts
npm run query -- credentials    # last 50 captured hashes
npm run query -- sessions       # session log
npm run query -- runs           # last 20 runs (with scope_authorized flag)
```

## Gotchas

- **`scope_authorized` is stored on every run row** so you have an audit trail proving the flag was present.
- **`credentials.password` is plaintext when captured**. Do not commit `attack.db`. `.gitignore` covers it.
- **Responder needs `sudo`** to bind port 445/139/80. Wrap with `sudo -E npm run responder ...` so the venv/npm path env is preserved.
- **NetExec renamed from crackmapexec** — old scripts referring to `cme` won't find the binary.
- **Nothing to see against external gov.hu targets in the current engagement** — Responder is LAN-only, NetExec needs credentials we don't have. This workspace exists for when the engagement scope expands into an internal segment (or for training in a lab).
