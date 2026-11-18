#!/usr/bin/env bash
# Reports where the bytes of the production Worker wasm go, and fails if it is
# over budget or links a forbidden package. See docs/CI.md ("Lint, size
# and dependencies").
#
# It does not build anything: `make size` builds build/app.wasm and the
# `tinygo -size full` report once (the same build e2e uses; CI builds them in
# its `build` job and passes them along as an artifact) and hands them in.
#
# Gates (fail the check):
#   - raw wasm size above MAX_WASM_BYTES
#   - a FORBID package (test-only stdlib) linked into the production binary
# Informational:
#   - gzip size, top packages by flash, and which WATCH packages are linked, so
#     a PR author notices a newly linked heavy dependency.
#
# Env:
#   MAX_WASM_BYTES  raw budget in bytes (default below); raise it deliberately
#                   in a PR when a feature justifies it
#   TOP             how many packages to list (default 15)
#   WASM            path to the built production wasm (required, unless
#                   WASM_BYTES is given)
#   SIZE_REPORT     path to the `tinygo -size full` table (required)
#   WASM_BYTES      raw size to use instead of measuring WASM (used to test the
#                   parser against a canned report)
set -euo pipefail
cd "$(dirname "$0")/.."

MAX_WASM_BYTES="${MAX_WASM_BYTES:-3400000}"
TOP="${TOP:-15}"

# Heavy packages that are NOT in the baseline build, so seeing one linked means
# something new pulled it in. Matched as whole import paths. Not failures: the
# byte budget decides that. Packages already linked (net/http, reflect, fmt,
# crypto/x509, math/big, ...) are deliberately absent: they would always print
# and hide real changes. Add a package here when it is worth noticing.
WATCH=(encoding/json database/sql crypto/tls log/slog)
# Test-only stdlib must never reach production.
FORBID=(testing net/http/httptest)

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

: "${SIZE_REPORT:?SIZE_REPORT is required (make size builds it)}"
cp "$SIZE_REPORT" "$tmp/size.txt"

if [ -n "${WASM_BYTES:-}" ]; then
  raw="$WASM_BYTES"
  gz="n/a"
else
  : "${WASM:?WASM is required (make size builds it)}"
  raw=$(stat -c %s "$WASM")
  gz=$(gzip -9 -c "$WASM" | wc -c)
fi

# One row per package from the `-size full` table: "<flash> <import path>".
# The path is normalised: the GOROOT prefix is dropped so stdlib packages read
# as "net/http", and module packages keep their full import path.
awk -F'|' '
  NF == 3 && $3 !~ /package|---/ {
    split($2, a, " ")
    pkg = $3
    gsub(/^ +| +$/, "", pkg)
    sub(/^\/usr\/lib\/go\/src\//, "", pkg)
    sub(/^.*\/go\/src\//, "", pkg)
    if (pkg != "total") print a[1] "\t" pkg
  }' "$tmp/size.txt" >"$tmp/pkgs.txt"

echo "== production wasm size =="
printf "raw:    %9s bytes (budget %d)\n" "$raw" "$MAX_WASM_BYTES"
printf "gzip:   %9s bytes (informational)\n" "$gz"

echo
echo "== top $TOP packages by flash =="
sort -t "$(printf '\t')" -k1,1nr "$tmp/pkgs.txt" | head -n "$TOP" | awk -F'\t' '{printf "%9d  %s\n", $1, $2}'

echo
echo "== watched packages linked in =="
found=0
for p in "${WATCH[@]}"; do
  if awk -F'\t' -v p="$p" '$2 == p { f = 1 } END { exit !f }' "$tmp/pkgs.txt"; then
    echo "  linked: $p"
    found=1
  fi
done
[ "$found" -eq 1 ] || echo "  (none)"

fail=0
for p in "${FORBID[@]}"; do
  if awk -F'\t' -v p="$p" '$2 == p { f = 1 } END { exit !f }' "$tmp/pkgs.txt"; then
    echo "FAIL: test-only package linked into production build: $p" >&2
    fail=1
  fi
done

if [ "$raw" -gt "$MAX_WASM_BYTES" ]; then
  echo "FAIL: raw size $raw exceeds budget $MAX_WASM_BYTES" >&2
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo
  echo "size ok"
fi
exit "$fail"
