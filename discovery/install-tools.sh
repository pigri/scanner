#!/usr/bin/env bash
# Install the OSINT / passive-recon tools used by discovery wrappers.
set -euo pipefail

need() { command -v "$1" >/dev/null 2>&1; }
echo_step() { printf '\n== %s ==\n' "$*"; }

# --- apt (fierce + dnsenum only — theharvester removed from Ubuntu 24.04) ---
if ! need fierce || ! need dnsenum; then
  echo_step 'Installing apt packages (fierce, dnsenum)'
  sudo apt-get update
  sudo apt-get install -y fierce dnsenum
fi

# theHarvester — install via pipx (apt package is gone in Ubuntu 24.04)
if ! need theHarvester && ! need theharvester; then
  echo_step 'Installing theHarvester via pipx'
  if ! need pipx; then sudo apt-get install -y pipx && pipx ensurepath; fi
  pipx install theHarvester
fi

# --- Go tools (projectdiscovery) ---
GO_BIN="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
if ! need go; then sudo apt-get install -y golang-go; fi

if ! need subfinder && [ ! -x "$GO_BIN/subfinder" ]; then
  echo_step 'Installing subfinder via go install'
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
fi

# --- amass (Go) ---
if ! need amass && [ ! -x "$GO_BIN/amass" ]; then
  echo_step 'Installing amass via go install'
  go install github.com/owasp-amass/amass/v4/...@master
fi

case ":$PATH:" in
  *":$GO_BIN:"*) ;;
  *)
    echo "add to your profile: export PATH=\"\$PATH:$GO_BIN\""
    export PATH="$PATH:$GO_BIN"
    ;;
esac

echo_step 'Done. Verify:'
for t in subfinder amass fierce dnsenum; do
  if need "$t"; then printf '  ok  %s (%s)\n' "$t" "$(command -v "$t")"
  else printf '  MISSING %s\n' "$t"; fi
done
# theHarvester ships lowercase and mixed-case aliases on different distros
if need theHarvester; then printf '  ok  %s (%s)\n' theHarvester "$(command -v theHarvester)"
elif need theharvester; then printf '  ok  %s (%s)\n' theharvester "$(command -v theharvester)"
else printf '  MISSING theHarvester (or theharvester)\n'
fi
