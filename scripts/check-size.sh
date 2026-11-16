#!/usr/bin/env bash
# Builds the production Worker wasm with TinyGo, reports where the bytes go, and
# fails if it is over budget or links a forbidden package. See docs/devops.md
# ("Wasm size budget").
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
#   SIZE_REPORT     if set, read this `tinygo -size full` table instead of
#                   building (used to test the parser); also needs WASM_BYTES
#   WASM_BYTES      raw size to use with SIZE_REPORT
set -euo pipefail
cd "$(dirname "$0")/.."

MAX_WASM_BYTES="${MAX_WASM_BYTES:-2200000}"
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

if [ -n "${SIZE_REPORT:-}" ]; then
  cp "$SIZE_REPORT" "$tmp/size.txt"
  raw="${WASM_BYTES:?WASM_BYTES is required with SIZE_REPORT}"
  gz="n/a"
else
  # Production configuration: no build tags. Put the repo-local TinyGo (from
  # `npm run setup:ci`) first on PATH when present, as `npm run build` does.
  PATH="$PWD/.tools/tinygo/bin:$PATH"
  tinygo build -o "$tmp/app.wasm" -target wasm -no-debug ./cmd/worker
  tinygo build -o "$tmp/full.wasm" -target wasm -size full ./cmd/worker >"$tmp/size.txt" 2>&1
  raw=$(stat -c %s "$tmp/app.wasm")
  gz=$(gzip -9 -c "$tmp/app.wasm" | wc -c)
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
