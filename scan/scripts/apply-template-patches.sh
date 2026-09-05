#!/usr/bin/env bash
# Idempotently re-apply local nuclei-template patches after a template refresh.
# `nuclei -update-templates` overwrites everything in ~/nuclei-templates from
# projectdiscovery/nuclei-templates HEAD — any local FP-fixes get lost. This
# script re-copies our fixed versions from scan/patches/*.fixed.yaml back into
# place. Wired into deploy/nuclei-update-templates.service so it runs after
# every nightly refresh.
#
# Add new patches by:
#   1. Editing the template in ~/nuclei-templates/
#   2. cp'ing the result to scan/patches/<template-id>.fixed.yaml
#   3. Adding a line to PATCHES below
set -euo pipefail

TEMPLATES_DIR="${TEMPLATES_DIR:-$HOME/nuclei-templates}"
PATCHES_DIR="$(cd "$(dirname "$0")/.." && pwd)/patches"

# One entry per patch: "<fixed-file-in-patches>|<destination-in-templates>"
PATCHES=(
  "snmpv3-detect.fixed.yaml|javascript/udp/detection/snmpv3-detect.yaml"
)

applied=0 unchanged=0
for entry in "${PATCHES[@]}"; do
  src="${entry%|*}"
  dst="${entry#*|}"
  src_path="$PATCHES_DIR/$src"
  dst_path="$TEMPLATES_DIR/$dst"
  if [ ! -f "$src_path" ]; then
    echo "  WARN: patch source missing: $src_path" >&2
    continue
  fi
  if [ ! -f "$dst_path" ]; then
    echo "  WARN: template destination missing: $dst_path" >&2
    continue
  fi
  if cmp -s "$src_path" "$dst_path"; then
    unchanged=$((unchanged+1))
    echo "  = $dst (already patched)"
  else
    cp "$src_path" "$dst_path"
    applied=$((applied+1))
    echo "  ✓ patched $dst"
  fi
done
echo "template-patches: $applied applied, $unchanged already in place"
