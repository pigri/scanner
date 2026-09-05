#!/usr/bin/env bash
# Install NetExec + Responder. These are attack-class tools; misuse against
# unauthorized infrastructure is a criminal offense.
set -euo pipefail

need() { command -v "$1" >/dev/null 2>&1; }
echo_step() { printf '\n== %s ==\n' "$*"; }

if ! need pipx; then
  echo_step 'Installing pipx'
  sudo apt-get update
  sudo apt-get install -y pipx
  pipx ensurepath
fi

if ! need responder && ! need Responder; then
  echo_step 'Installing Responder'
  if sudo apt-get install -y responder 2>/dev/null; then
    :
  else
    echo '  apt package not available — installing from GitHub via pipx'
    pipx install git+https://github.com/lgandx/Responder.git
  fi
fi

if ! need netexec && ! need nxc; then
  echo_step 'Installing NetExec via pipx'
  pipx install git+https://github.com/Pennyw0rth/NetExec
fi

echo_step 'Done. Verify:'
for t in responder Responder netexec nxc; do
  if need "$t"; then printf '  ok  %s (%s)\n' "$t" "$(command -v "$t")"
  fi
done
for pair in "responder:Responder" "netexec:nxc"; do
  a="${pair%:*}"; b="${pair#*:}"
  if ! need "$a" && ! need "$b"; then printf '  MISSING %s or %s\n' "$a" "$b"; fi
done

cat <<'NOTE'

Before running anything in this workspace:
  1. Write scope.txt (suffix + CIDR allowlist matching your written engagement scope).
  2. Every attack tool requires --scope <file> AND --yes-i-am-authorized.
     No exceptions — the gate refuses to run otherwise.
  3. Responder is LAN-only; it needs to be on the same broadcast domain as targets.
     For external gov.hu targets, it will not see or intercept anything.
NOTE
