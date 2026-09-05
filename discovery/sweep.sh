#!/usr/bin/env bash
# Convenience runner. Edit the flags below (or set env vars) for your target.
# Runs the sweep in the background and prints the pid.
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -d node_modules ]; then
  echo "installing deps..."
  npm install --silent
fi

QUERY="${QUERY:-site:.gov.hu -site:nki.gov.hu -site:nbsz.gov.hu}"
TERMS="${TERMS:-kormány,minisztérium,önkormányzat,hivatal,intézmény,pályázat,rendelet,2024,2025}"
REGIONS="${REGIONS:-wt-wt,hu-hu,us-en,de-de}"
SUFFIX="${SUFFIX:-.gov.hu}"
EXCLUDE="${EXCLUDE:-nki.gov.hu,nbsz.gov.hu}"
OUT="${OUT:-domains.txt}"
LOG="${LOG:-sweep.log}"
# Rotate exit IP on rate-limit. Set ROTATE="" to disable.
ROTATE="${ROTATE:-windscribe-cli ip rotate}"

ROTATE_ARGS=()
if [ -n "$ROTATE" ]; then
  ROTATE_ARGS=(--rotate-cmd "$ROTATE")
fi

: > "$LOG"
echo "starting sweep in background; tail -f $LOG"
nohup npx tsx src/ddg-sweep.ts "$QUERY" \
  --terms "$TERMS" \
  --regions "$REGIONS" \
  --suffix "$SUFFIX" \
  --exclude "$EXCLUDE" \
  --out "$OUT" \
  --log "$LOG" \
  "${ROTATE_ARGS[@]}" \
  >/dev/null 2>&1 &
echo "pid=$!"
