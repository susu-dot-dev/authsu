#!/usr/bin/env bash
# Installs the pinned TinyGo (see tools.env) into .tools/tinygo, verifying the
# release tarball against the SHA-256 pinned in tools.env. Used by CI and by
# Cloudflare Workers Builds, whose image has Go and Node but not TinyGo.
#
# `npm run build` puts .tools/tinygo/bin on PATH when it exists, so:
#   npm run setup:ci && npm run build
# Linux amd64 only (the CI and Workers Builds platform). Idempotent.
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck source=../tools.env
. ./tools.env

dest=".tools/tinygo"
if [ -x "$dest/bin/tinygo" ] &&
  "$dest/bin/tinygo" version | grep -q "^tinygo version ${TINYGO_VERSION} "; then
  echo "tinygo ${TINYGO_VERSION} already installed in $dest"
  exit 0
fi

file="tinygo${TINYGO_VERSION}.linux-amd64.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/$file" \
  "https://github.com/tinygo-org/tinygo/releases/download/v${TINYGO_VERSION}/${file}"
echo "${TINYGO_LINUX_AMD64_SHA256}  $tmp/$file" | sha256sum -c -

rm -rf "$dest"
mkdir -p .tools
tar -C .tools -xzf "$tmp/$file"
"$dest/bin/tinygo" version
