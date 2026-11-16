#!/usr/bin/env bash
# Installs the pinned TinyGo (see tools.env) into .tools/tinygo. The release
# tarball is ALWAYS verified against the SHA-256 pinned in tools.env before it
# is extracted, whether it was just downloaded or came from a cache. Used by CI
# and by Cloudflare Workers Builds, whose image has Go and Node but not TinyGo.
#
# `npm run build` puts .tools/tinygo/bin on PATH when it exists, so:
#   npm run setup:ci && npm run build
#
# The tarball is kept in TINYGO_CACHE_DIR (default .tools/cache) so CI can cache
# that directory and skip the download. Cache the tarball, never the extracted
# tree: a cache is not signed, and an extracted tree cannot be re-verified
# cheaply, so a poisoned cache entry would otherwise run unchecked. A cached
# tarball that fails the checksum is discarded and downloaded again.
#
# Linux amd64 only (the CI and Workers Builds platform). Idempotent: extraction
# is skipped only when a marker records the exact verified tarball hash.
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck source=../tools.env
. ./tools.env

dest=".tools/tinygo"
marker=".tools/tinygo.sha256"
cache="${TINYGO_CACHE_DIR:-.tools/cache}"
file="tinygo${TINYGO_VERSION}.linux-amd64.tar.gz"
tarball="$cache/$file"

# Already extracted from a tarball with exactly this hash: nothing to do. The
# marker only records what was verified; it does not vouch for the tree itself,
# which is why the tree is never what gets cached.
if [ -x "$dest/bin/tinygo" ] && [ -f "$marker" ] &&
  [ "$(cat "$marker")" = "$TINYGO_LINUX_AMD64_SHA256" ]; then
  echo "tinygo ${TINYGO_VERSION} already installed in $dest"
  exit 0
fi

verify() { echo "${TINYGO_LINUX_AMD64_SHA256}  $1" | sha256sum -c - >/dev/null 2>&1; }

mkdir -p "$cache"
if [ -f "$tarball" ] && verify "$tarball"; then
  echo "using cached $file (checksum verified)"
else
  [ ! -f "$tarball" ] || echo "cached $file failed its checksum; downloading again"
  part="$tarball.part"
  trap 'rm -f "$part"' EXIT
  curl -fsSL -o "$part" \
    "https://github.com/tinygo-org/tinygo/releases/download/v${TINYGO_VERSION}/${file}"
  # Verify before the file can ever be mistaken for a good cache entry.
  echo "${TINYGO_LINUX_AMD64_SHA256}  $part" | sha256sum -c -
  mv "$part" "$tarball"
fi

rm -rf "$dest" "$marker"
mkdir -p .tools
tar -C .tools -xzf "$tarball"
echo "$TINYGO_LINUX_AMD64_SHA256" >"$marker"
"$dest/bin/tinygo" version
