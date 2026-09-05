#!/usr/bin/env bash
# Install the Windscribe CLI on Debian/Ubuntu (amd64 or arm64).
# Requires sudo — run this manually.
set -euo pipefail

cd "$(dirname "$0")"

ARCH="$(dpkg --print-architecture)"
case "$ARCH" in
  amd64) URL='https://windscribe.com/install/desktop/linux_deb_x64_cli' ;;
  arm64) URL='https://windscribe.com/install/desktop/linux_deb_arm64_cli' ;;
  *) echo "unsupported arch: $ARCH"; exit 1 ;;
esac

DEB="windscribe-cli-${ARCH}.deb"
if [ ! -f "$DEB" ]; then
  echo "downloading $URL -> $DEB"
  curl -fsSL "$URL" -o "$DEB"
fi

echo "installing $DEB (needs sudo)"
sudo apt install -y "./$DEB"

echo
echo "next steps:"
echo "  1. windscribe-cli login          # interactive; enter your credentials"
echo "  2. windscribe-cli connect best   # pick a server"
echo "  3. windscribe-cli status         # verify"
echo "  4. ./sweep.sh                    # (or run ddg-sweep.js with --rotate-cmd)"
