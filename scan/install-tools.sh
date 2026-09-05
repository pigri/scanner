#!/usr/bin/env bash
# Install all scanning tools. Debian/Ubuntu focused. Prompts for sudo.
set -euo pipefail

need() { command -v "$1" >/dev/null 2>&1; }
need_either() { command -v "$1" >/dev/null 2>&1 || command -v "$2" >/dev/null 2>&1; }
echo_step() { printf '\n== %s ==\n' "$*"; }

# --- system packages (apt) ---
if ! need nmap || ! need masscan || ! need_either testssl.sh testssl || ! need wpscan \
   || ! need smbmap || ! need rpcclient || ! need arp-scan || ! need nbtscan; then
  echo_step 'Installing apt packages (nmap masscan testssl.sh smbmap smbclient arp-scan nbtscan)'
  sudo apt-get update
  # arp-scan and nbtscan are LAN-only; they're here for lab/internal work.
  sudo apt-get install -y nmap masscan testssl.sh smbmap smbclient arp-scan nbtscan
  if ! need wpscan; then
    sudo apt-get install -y ruby-full ruby-dev build-essential libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev libgmp-dev zlib1g-dev
    sudo gem install wpscan
  fi
fi

# --- web content-discovery / fuzzing / vuln tools available via apt ---
# dirb (content scanner), nikto (web-server vuln), sqlmap (SQLi), wafw00f (WAF
# fingerprint), sslscan (cipher enum), whatweb (tech id), wfuzz (fuzzer).
# All ship in Ubuntu 24.04 main/universe. (commix is NOT packaged — see clone group.)
APT_WEB=(dirb nikto sqlmap wafw00f sslscan whatweb wfuzz)
missing_apt=()
for p in "${APT_WEB[@]}"; do need "$p" || missing_apt+=("$p"); done
if [ "${#missing_apt[@]}" -gt 0 ]; then
  echo_step "Installing apt web tools: ${missing_apt[*]}"
  sudo apt-get update
  sudo apt-get install -y "${missing_apt[@]}"
fi

# enum4linux (Perl) was removed from Ubuntu 24.04 repos. Clone the upstream
# Perl script and drop it in /usr/local/bin.
if ! need enum4linux; then
  echo_step 'Installing enum4linux from GitHub (Ubuntu 24.04 dropped the apt package)'
  sudo apt-get install -y libnet-nbname-perl smbclient
  sudo curl -fsSL https://raw.githubusercontent.com/CiscoCXSecurity/enum4linux/master/enum4linux.pl -o /usr/local/bin/enum4linux
  sudo chmod +x /usr/local/bin/enum4linux
fi

# enum4linux-ng (Python rewrite) — not on PyPI; install from GitHub via pipx.
if ! need enum4linux-ng; then
  echo_step 'Installing enum4linux-ng from GitHub'
  if ! need pipx; then sudo apt-get install -y pipx && pipx ensurepath; fi
  pipx install 'git+https://github.com/cddmp/enum4linux-ng.git' \
    || echo '  WARN: enum4linux-ng install failed'
fi

# --- pipx helper (Python CLI tools) ---
install_pipx() {
  local spec="$1" bin="$2"
  need "$bin" && return 0
  if ! need pipx; then sudo apt-get install -y pipx && pipx ensurepath; fi
  echo_step "Installing $bin via pipx ($spec)"
  pipx install "$spec" || echo "  WARN: pipx install $spec failed"
}
# dirsearch (recursive content discovery), arjun (param discovery),
# sslyze (TLS analyzer), uro (URL dedup/filter), paramspider (archive params).
install_pipx dirsearch dirsearch
install_pipx arjun arjun
install_pipx sslyze sslyze
install_pipx uro uro
install_pipx 'git+https://github.com/devanshbatham/ParamSpider.git' paramspider
install_pipx checkdmarc checkdmarc

# autorecon (Tib3rius) — pipx
if ! need autorecon; then
  echo_step 'Installing autorecon via pipx'
  if ! need pipx; then sudo apt-get install -y pipx && pipx ensurepath; fi
  pipx install git+https://github.com/Tib3rius/AutoRecon.git
fi

# rustscan (Cargo) — Debian package is old, prefer cargo install
if ! need rustscan; then
  if need cargo; then
    echo_step 'Installing rustscan via cargo'
    cargo install rustscan
  else
    echo 'skip rustscan: install rustup first (https://rustup.rs)'
  fi
fi

# --- Cargo tools (feroxbuster, x8) ---
# feroxbuster: recursive content discovery w/ smart filtering.
# x8: hidden-parameter discovery.
install_cargo() {
  local crate="$1" bin="$2"
  need "$bin" && return 0
  if ! need cargo; then echo "  skip $bin: install rustup first (https://rustup.rs)"; return 0; fi
  echo_step "Installing $bin via cargo"
  cargo install "$crate" || echo "  WARN: cargo install $crate failed"
}
install_cargo feroxbuster feroxbuster
install_cargo x8 x8

# Some Debian/Ubuntu versions ship the testssl binary as /usr/bin/testssl (no .sh).
# The wrappers accept either, but a symlink keeps things predictable + matches upstream docs.
if ! need testssl.sh && need testssl; then
  echo_step 'Symlinking /usr/local/bin/testssl.sh -> /usr/bin/testssl (needs sudo)'
  sudo ln -sf "$(command -v testssl)" /usr/local/bin/testssl.sh
fi

# --- Go tools (projectdiscovery + web-recon ecosystem) ---
GO_BIN="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
if ! need go; then
  echo_step 'Installing Go (needed for httpx / nuclei / gowitness / content tools)'
  sudo apt-get install -y golang-go
fi

install_go_tool() {
  local pkg="$1" bin="$2"
  # Look for the binary in $GO_BIN too — it may not be on $PATH yet.
  if ! need "$bin" && [ ! -x "$GO_BIN/$bin" ]; then
    echo_step "Installing $bin via go install"
    go install "$pkg@latest" || echo "  WARN: go install $pkg failed"
  fi
}
# core probing + vuln
install_go_tool 'github.com/projectdiscovery/httpx/cmd/httpx' httpx
install_go_tool 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei' nuclei
install_go_tool 'github.com/sensepost/gowitness' gowitness
# port sweep (WG/tun-friendly alternative to masscan)
install_go_tool 'github.com/projectdiscovery/naabu/v2/cmd/naabu' naabu
# DNS layer — A/AAAA/CNAME/MX/TXT/NS batch resolver
install_go_tool 'github.com/projectdiscovery/dnsx/cmd/dnsx' dnsx
# secrets in downloaded web bundles (JS/JSON/env/config)
install_go_tool 'github.com/zricethezav/gitleaks/v8' gitleaks
# trufflehog (release tarball — go install fails on replace-directive'd module)
if ! need trufflehog && [ ! -x "$HOME/go/bin/trufflehog" ]; then
  echo_step 'Installing trufflehog from release tarball'
  tmp=$(mktemp -d) ; (
    cd "$tmp" && \
    curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v3.90.9/trufflehog_3.90.9_linux_amd64.tar.gz" -o th.tgz && \
    tar -xzf th.tgz && install -m 0755 trufflehog "$HOME/go/bin/trufflehog"
  ) || echo "  WARN: trufflehog install failed"
  rm -rf "$tmp"
fi
# kiterunner — API-route brute (from source; upstream go install is broken)
if ! need kr; then
  echo_step 'Installing kiterunner (source build — upstream go install is broken)'
  tmp=$(mktemp -d); (
    cd "$tmp" && \
    git clone --depth 1 https://github.com/assetnote/kiterunner.git && \
    cd kiterunner && make build && install -m 0755 dist/kr "$HOME/go/bin/kr"
  ) || echo "  WARN: kiterunner build failed"
  rm -rf "$tmp"
fi

# vulners.nse — nmap script for CVE tagging from product+version fingerprints
if [ ! -f /usr/share/nmap/scripts/vulners.nse ]; then
  echo_step 'Installing vulners.nse (nmap CVE-tagging script)'
  sudo curl -fsSL -o /usr/share/nmap/scripts/vulners.nse \
    https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse \
    && sudo nmap --script-updatedb >/dev/null 2>&1 \
    || echo "  WARN: vulners.nse install failed"
fi
# content discovery + fuzzing
install_go_tool 'github.com/OJ/gobuster/v3' gobuster
install_go_tool 'github.com/ffuf/ffuf/v2' ffuf
# crawling / spidering
install_go_tool 'github.com/projectdiscovery/katana/cmd/katana' katana
install_go_tool 'github.com/hakluke/hakrawler' hakrawler
# historical URL sourcing
install_go_tool 'github.com/lc/gau/v2/cmd/gau' gau
install_go_tool 'github.com/tomnomnom/waybackurls' waybackurls
# xss + custom-signature vuln scanning
install_go_tool 'github.com/hahwul/dalfox/v2' dalfox
install_go_tool 'github.com/jaeles-project/jaeles' jaeles
# stream plumbing (dedup / rewrite)
install_go_tool 'github.com/tomnomnom/anew' anew
install_go_tool 'github.com/tomnomnom/qsreplace' qsreplace

case ":$PATH:" in
  *":$GO_BIN:"*) ;;
  *)
    echo_step "Go tools installed at $GO_BIN but that dir is not on \$PATH"
    echo "Add to your shell profile (~/.bashrc, ~/.zshrc):"
    echo "  export PATH=\"\$PATH:$GO_BIN\""
    echo "Then re-open the shell OR run 'source ~/.bashrc'"
    # Export for this session so the verify loop below sees them.
    export PATH="$PATH:$GO_BIN"
    ;;
esac

# --- git-clone tools with no clean package (jwt_tool, NoSQLMap, tplmap) ---
# Cloned into $TOOLS_DIR; thin wrappers dropped in /usr/local/bin.
TOOLS_DIR="${TOOLS_DIR:-$HOME/tools}"
mkdir -p "$TOOLS_DIR"
clone_wrap() {
  local repo="$1" dir="$2" entry="$3" wrapper="$4" interp="$5"
  if need "$wrapper"; then return 0; fi
  if [ ! -d "$TOOLS_DIR/$dir" ]; then
    echo_step "Cloning $dir"
    git clone --depth 1 "$repo" "$TOOLS_DIR/$dir" || { echo "  WARN: clone $repo failed"; return 0; }
  fi
  # requirements.txt, if present
  if [ -f "$TOOLS_DIR/$dir/requirements.txt" ] && [ "$interp" = python3 ]; then
    pip3 install --user -r "$TOOLS_DIR/$dir/requirements.txt" >/dev/null 2>&1 || true
  fi
  printf '#!/usr/bin/env bash\nexec %s "%s/%s" "$@"\n' "$interp" "$TOOLS_DIR/$dir" "$entry" \
    | sudo tee "/usr/local/bin/$wrapper" >/dev/null
  sudo chmod +x "/usr/local/bin/$wrapper"
}
clone_wrap https://github.com/ticarpi/jwt_tool        jwt_tool  jwt_tool.py python3 jwt_tool python3
clone_wrap https://github.com/codingo/NoSQLMap        NoSQLMap  nosqlmap.py python3 nosqlmap python3
clone_wrap https://github.com/commixproject/commix    commix    commix.py   python3 commix   python3
# tplmap is legacy python2 — wrapper points at python2 if available, else python.
if need python2; then TPL_PY=python2; else TPL_PY=python; fi
clone_wrap https://github.com/epinna/tplmap       tplmap    tplmap.py   "$TPL_PY" tplmap "$TPL_PY"

# --- Nuclei templates ---
if need nuclei; then
  echo_step 'Updating nuclei templates'
  nuclei -update-templates || true
fi

echo_step 'Done. Verify:'
found_all=1
verify() {
  local name="$1"; shift
  for bin in "$@"; do
    if need "$bin"; then printf '  ok  %-14s (%s)\n' "$name" "$(command -v "$bin")"; return; fi
  done
  printf '  MISSING %s\n' "$name"; found_all=0
}
# port / host scanning
verify nmap          nmap
verify masscan       masscan
verify rustscan      rustscan
verify naabu         naabu
verify dnsx          dnsx
verify kr            kr
verify autorecon     autorecon
# secrets scanning
verify gitleaks      gitleaks
verify trufflehog    trufflehog
# tls
verify testssl       testssl.sh testssl
verify sslscan       sslscan
verify sslyze        sslyze
# http probe / tech id
verify httpx         httpx
verify whatweb       whatweb
verify wafw00f       wafw00f
verify gowitness     gowitness
# content discovery / fuzzing
verify gobuster      gobuster
verify dirsearch     dirsearch
verify feroxbuster   feroxbuster
verify ffuf          ffuf
verify dirb          dirb
verify wfuzz         wfuzz
# crawling + url sourcing
verify katana        katana
verify hakrawler     hakrawler
verify gau           gau
verify waybackurls   waybackurls
# param discovery
verify arjun         arjun
verify paramspider   paramspider
verify x8            x8
# vuln scanning / injection
verify nuclei        nuclei
verify nikto         nikto
verify jaeles        jaeles
verify dalfox        dalfox
verify wpscan        wpscan
verify sqlmap        sqlmap
verify commix        commix
verify nosqlmap      nosqlmap
verify tplmap        tplmap
verify jwt_tool      jwt_tool
# stream plumbing
verify anew          anew
verify qsreplace     qsreplace
verify uro           uro
# smb / netbios (LAN-oriented)
verify enum4linux    enum4linux
verify enum4linux-ng enum4linux-ng
verify smbmap        smbmap
verify rpcclient     rpcclient
verify arp-scan      arp-scan       # LAN-only, no-op vs remote targets
verify nbtscan       nbtscan        # LAN-only, no-op vs remote targets
# email hygiene
verify checkdmarc    checkdmarc

echo
echo 'Recommended env vars:'
echo '  export WPSCAN_API_TOKEN=<from wpscan.com>   # optional, unlocks CVE data'
echo
echo 'Not CLI-installable (manual / GUI — noted for completeness):'
echo '  Burp Suite Extensions : install extensions inside Burp (BApp Store).'
echo '  ZAP Proxy             : sudo snap install zaproxy --classic   (or download from zaproxy.org)'
echo '  GraphQL-Voyager       : web UI, not a CLI. For GraphQL testing use'
echo '                          `pipx install graphql-cop` or inql instead.'

if [ "$found_all" -ne 1 ]; then
  echo
  echo 'One or more tools still missing. If Go/Cargo tools are the issue, add their bin dir to $PATH and re-run.'
  exit 1
fi
