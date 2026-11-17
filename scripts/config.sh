#!/usr/bin/env bash
# Helpers to read and write the deployment configuration: the AUTH_HMAC_SECRET
# secret and the API_ORIGIN and UI_ORIGIN vars. See docs/runbook.md
# ("Secrets and variables") for how they are stored and why. Run through
# `make config-*`; see `make help`.
#
#   config.sh get                      show every value and where it is stored
#   config.sh set-vars API UI          write API_ORIGIN and UI_ORIGIN into wrangler.jsonc
#   config.sh set-secret               generate AUTH_HMAC_SECRET and upload it
#   config.sh set-secret --stdin       upload the secret read from stdin instead
#   config.sh set-secret --local       write it to .dev.vars instead of Cloudflare
#   config.sh dev-vars                 write AUTH_HMAC_SECRET and FIRST_RUN_SECRET to .dev.vars
#
# A secret is never printed, never put on a command line (where `ps` shows it)
# and never written to disk unless --local says so. Cloudflare cannot return a
# secret's value once set, so `get` can only say whether it exists.
#
# Env:
#   WRANGLER_CONFIG  config file holding the vars (default wrangler.jsonc)
#   DEV_VARS         file --local writes to (default .dev.vars)
#   WRANGLER         command that runs wrangler (default "npx wrangler")
set -euo pipefail
cd "$(dirname "$0")/.."

CONFIG="${WRANGLER_CONFIG:-wrangler.jsonc}"
DEV_VARS="${DEV_VARS:-.dev.vars}"
WRANGLER="${WRANGLER:-npx wrangler}"

SECRET=AUTH_HMAC_SECRET
# The first-run code (internal/firstrun.SecretName), needed only to bootstrap
# the first administrator on a fresh database.
FIRST_RUN_SECRET=FIRST_RUN_SECRET
VARS=(API_ORIGIN UI_ORIGIN)

# Registration refuses a secret shorter than this (registration.MinSecretLen).
MIN_SECRET_LEN=32
# 32 random bytes is 43 base64url characters.
SECRET_BYTES=32

die() { echo "config: $*" >&2; exit 1; }

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
  exit "${1:-2}"
}

# var_get NAME -> prints the value of a var in $CONFIG, or nothing if unset.
# The file is JSONC, but the vars are single-line `"NAME": "value"` entries, so
# a line match is enough and avoids a JSONC parser dependency.
var_get() {
  local name=$1
  sed -n -E "s/^[[:space:]]*\"$name\":[[:space:]]*\"(.*)\",?[[:space:]]*\$/\1/p" "$CONFIG" | head -n1
}

# json_escape VALUE -> VALUE escaped for use inside a JSON string.
json_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  printf '%s' "$s"
}

# sed_escape VALUE -> VALUE escaped for the replacement side of s|...|...|.
sed_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//&/\\&}
  s=${s//|/\\|}
  printf '%s' "$s"
}

# var_set NAME VALUE -> rewrites the existing entry in place, keeping comments,
# indentation and the trailing comma. Fails if the entry is not there, rather
# than guessing where to add one.
var_set() {
  local name=$1 value=$2 escaped tmp
  [ -n "$(var_get "$name")" ] || [ -n "$(grep -E "^[[:space:]]*\"$name\":" "$CONFIG" || true)" ] ||
    die "no \"$name\" entry in $CONFIG; add it under \"vars\" first"
  escaped="$(sed_escape "$(json_escape "$value")")"
  tmp="$(mktemp "$CONFIG.XXXXXX")"
  sed -E "s|^([[:space:]]*\"$name\":[[:space:]]*\")(.*)(\",?[[:space:]]*)\$|\\1$escaped\\3|" "$CONFIG" >"$tmp"
  cat "$tmp" >"$CONFIG" # keep the file's mode and inode
  rm -f "$tmp"
}

# validate_origin NAME VALUE: the same rule as deploy.ParseOrigin: a scheme and a
# host with an optional numeric port and nothing else, lower case, https for any
# host and plain http for localhost only.
validate_origin() {
  local name=$1 value=$2
  case $value in
    https://*) ;;
    http://localhost | http://localhost:*) ;;
    *) die "$name must be an https:// origin (http only for localhost): $value" ;;
  esac
  case ${value#*://} in
    */* | *\?* | *#* | *@*) die "$name must be an origin only, with no path, query, fragment or user info: $value" ;;
  esac
  case $value in
    *[[:space:]]*) die "$name must not contain whitespace: $value" ;;
    *[A-Z]*) die "$name must be lower case, as a browser sends it: $value" ;;
  esac
  # After the scheme, a colon introduces the port, which must be digits.
  local authority=${value#*://}
  if [[ $authority == *:* ]]; then
    case ${authority#*:} in
      '' | *[!0-9]*) die "$name has an invalid port: $value" ;;
    esac
  fi
}

# host_of ORIGIN -> the hostname of an origin, without scheme or port. This is
# the relying party ID the Worker derives from UI_ORIGIN.
host_of() {
  local h=${1#*://}
  printf '%s' "${h%%:*}"
}

secret_present() { # -> 0 when the Worker has the secret
  local out
  out="$($WRANGLER secret list --format json 2>/dev/null)" || return 2
  printf '%s' "$out" | grep -q "\"name\": *\"$SECRET\""
}

cmd_get() {
  local name value

  echo "Vars (plaintext, in $CONFIG, deployed with the Worker):"
  for name in "${VARS[@]}"; do
    value="$(var_get "$name")"
    printf '  %-12s %s\n' "$name" "${value:-<unset>}"
  done

  echo
  echo "Secret (encrypted, set on Cloudflare; its value can never be read back):"
  if secret_present; then
    printf '  %-16s set\n' "$SECRET"
  else
    case $? in
      1) printf '  %-16s NOT SET (make config-set-secret)\n' "$SECRET" ;;
      *) printf '  %-16s unknown (wrangler could not list secrets: not logged in, or the Worker is not deployed yet)\n' "$SECRET" ;;
    esac
  fi

  echo
  if [ -f "$DEV_VARS" ]; then
    if grep -q -E "^$SECRET=.{$MIN_SECRET_LEN,}" "$DEV_VARS"; then
      echo "Local dev ($DEV_VARS): $SECRET set"
    else
      echo "Local dev ($DEV_VARS): $SECRET missing or shorter than $MIN_SECRET_LEN characters"
    fi
  else
    echo "Local dev ($DEV_VARS): not present (make config-set-secret ARGS=--local)"
  fi
}

cmd_set_vars() {
  [ $# -eq 2 ] || { echo "usage: config.sh set-vars API_ORIGIN UI_ORIGIN" >&2; exit 2; }
  local api=$1 ui=$2

  validate_origin API_ORIGIN "$api"
  validate_origin UI_ORIGIN "$ui"

  # The relying party ID is the UI origin's host, and a passkey is bound to it.
  local current current_id id
  current="$(var_get UI_ORIGIN)"
  id="$(host_of "$ui")"
  if [ -n "$current" ]; then
    current_id="$(host_of "$current")"
    if [ "$current_id" != "$id" ] && [ "$current_id" != localhost ] && [ -z "${CONFIRM_RP_ID_CHANGE:-}" ]; then
      die "UI_ORIGIN's host is already '$current_id', which is the relying party ID. Changing it to '$id' invalidates every registered passkey. Re-run with CONFIRM_RP_ID_CHANGE=1 if that is intended."
    fi
  fi

  var_set API_ORIGIN "$api"
  var_set UI_ORIGIN "$ui"

  echo "Wrote API_ORIGIN and UI_ORIGIN to $CONFIG (relying party ID: $id)."
  echo "Vars ship with the code: they take effect on the next deploy (npx wrangler deploy)."
}

generate_secret() {
  command -v openssl >/dev/null || die "openssl is required to generate a secret (or use --stdin)"
  # base64url, no padding: safe in a dotenv file and in a shell.
  openssl rand -base64 "$SECRET_BYTES" | tr '+/' '-_' | tr -d '=\n'
}

cmd_set_secret() {
  local mode=generate target=remote arg value
  for arg in "$@"; do
    case $arg in
      --stdin) mode=stdin ;;
      --local) target=local ;;
      *) usage ;;
    esac
  done

  if [ "$mode" = stdin ]; then
    IFS= read -r value || [ -n "$value" ] || die "no secret on stdin"
  else
    value="$(generate_secret)"
  fi
  [ "${#value}" -ge "$MIN_SECRET_LEN" ] ||
    die "$SECRET must be at least $MIN_SECRET_LEN characters; registration refuses a shorter one"

  if [ "$target" = local ]; then
    set_local "$value"
    return
  fi

  if secret_present && [ -z "${CONFIRM_SECRET_ROTATE:-}" ]; then
    die "$SECRET is already set. Replacing it invalidates every registration begun but not finished, and anything else signed with a key derived from it. Re-run with CONFIRM_SECRET_ROTATE=1 if that is intended."
  fi

  # The value goes over stdin, so it is never in argv or the process list.
  printf '%s\n' "$value" | $WRANGLER secret put "$SECRET"
  echo "$SECRET uploaded. Setting a secret deploys a new version of the Worker."
}

# set_local VALUE -> writes AUTH_HMAC_SECRET into $DEV_VARS, replacing a line
# already there and leaving every other line alone. The file is created 0600.
set_local() {
  local value=$1 tmp
  if [ -f "$DEV_VARS" ] && grep -q -E "^$SECRET=" "$DEV_VARS" && [ -z "${CONFIRM_SECRET_ROTATE:-}" ]; then
    die "$SECRET is already in $DEV_VARS. Re-run with CONFIRM_SECRET_ROTATE=1 to replace it."
  fi
  umask 077
  touch "$DEV_VARS"
  tmp="$(mktemp "$DEV_VARS.XXXXXX")"
  { grep -v -E "^$SECRET=" "$DEV_VARS" || true; printf '%s=%s\n' "$SECRET" "$value"; } >"$tmp"
  cat "$tmp" >"$DEV_VARS"
  rm -f "$tmp"
  echo "$SECRET written to $DEV_VARS (git-ignored)."
}

# dev_vars_set NAME VALUE -> sets NAME in $DEV_VARS unless it is already there,
# leaving every other line alone. Prints whether it wrote or kept the entry.
# The file is created 0600. Existing values are never replaced: rotating a
# secret under a running local database would orphan its first-run invitation.
dev_vars_set() {
  local name=$1 value=$2 tmp
  if [ -f "$DEV_VARS" ] && grep -q -E "^$name=.{$MIN_SECRET_LEN,}" "$DEV_VARS"; then
    echo "  $name: already set, kept"
    return
  fi
  umask 077
  touch "$DEV_VARS"
  tmp="$(mktemp "$DEV_VARS.XXXXXX")"
  { grep -v -E "^$name=" "$DEV_VARS" || true; printf '%s=%s\n' "$name" "$value"; } >"$tmp"
  cat "$tmp" >"$DEV_VARS"
  rm -f "$tmp"
  echo "  $name: generated"
}

# cmd_dev_vars generates every secret `make dev` needs into $DEV_VARS. It is
# idempotent: values already present are kept, so it is safe to re-run.
cmd_dev_vars() {
  [ $# -eq 0 ] || usage
  echo "Writing $DEV_VARS (git-ignored, mode 0600):"
  dev_vars_set "$SECRET" "$(generate_secret)"
  dev_vars_set "$FIRST_RUN_SECRET" "$(generate_secret)"
  echo
  echo "Next: make dev. To change a value, edit $DEV_VARS or delete it and re-run."
  echo "The first-run invitation code is the $FIRST_RUN_SECRET value in $DEV_VARS."
}

main() {
  local cmd=${1:-}
  [ $# -gt 0 ] && shift
  case $cmd in
    get) cmd_get "$@" ;;
    set-vars) cmd_set_vars "$@" ;;
    set-secret) cmd_set_secret "$@" ;;
    dev-vars) cmd_dev_vars "$@" ;;
    -h | --help | help) usage 0 ;;
    *) usage ;;
  esac
}

main "$@"
