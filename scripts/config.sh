#!/usr/bin/env bash
# Helpers to read and write the registration configuration: the AUTH_HMAC_SECRET
# secret and the RP_ID, RP_ORIGIN and RP_NAME vars. See docs/devops.md
# ("Secrets and variables") for what each one is and why they are stored as they
# are. Run through `make config-*`; see `make help`.
#
#   config.sh get                      show every value and where it is stored
#   config.sh set-vars ID ORIGIN NAME  write the RP_* vars into wrangler.jsonc
#   config.sh set-secret               generate AUTH_HMAC_SECRET and upload it
#   config.sh set-secret --stdin       upload the secret read from stdin instead
#   config.sh set-secret --local       write it to .dev.vars instead of Cloudflare
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
VARS=(RP_ID RP_ORIGIN RP_NAME)

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

validate_origin() {
  case $1 in
    https://*) ;;
    http://localhost | http://localhost:* | http://127.0.0.1 | http://127.0.0.1:*) ;;
    *) die "RP_ORIGIN must be an https:// origin (http only for localhost): $1" ;;
  esac
  case ${1#*://} in
    */* | *\?* | *#*) die "RP_ORIGIN must be an origin only, with no path, query or fragment: $1" ;;
  esac
  case $1 in
    *[[:space:]]*) die "RP_ORIGIN must not contain whitespace: $1" ;;
  esac
}

validate_rp_id() {
  case $1 in
    '') die "RP_ID must not be empty" ;;
    *://* | */* | *:* | *[[:space:]]*) die "RP_ID must be a bare domain such as auth.example.com, not a URL or host:port: $1" ;;
  esac
}

# host_of ORIGIN -> the hostname of an origin, without scheme or port.
host_of() {
  local h=${1#*://}
  printf '%s' "${h%%:*}"
}

# An RP ID must equal the origin's host or be a registrable suffix of it, or the
# browser rejects every ceremony. A suffix check cannot know the public suffix
# list, so this only catches the clear mismatches.
validate_rp_id_matches_origin() {
  local id=$1 host
  host="$(host_of "$2")"
  if [ "$host" != "$id" ] && [[ $host != *".$id" ]]; then
    die "RP_ID '$id' must equal the origin's host '$host' or be a parent domain of it"
  fi
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
    printf '  %-10s %s\n' "$name" "${value:-<unset>}"
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
  [ $# -eq 3 ] || { echo "usage: config.sh set-vars RP_ID RP_ORIGIN RP_NAME" >&2; exit 2; }
  local id=$1 origin=$2 name=$3

  validate_rp_id "$id"
  validate_origin "$origin"
  validate_rp_id_matches_origin "$id" "$origin"
  [ -n "$name" ] || die "RP_NAME must not be empty"

  local current
  current="$(var_get RP_ID)"
  if [ -n "$current" ] && [ "$current" != "$id" ] && [ "$current" != localhost ] && [ -z "${CONFIRM_RP_ID_CHANGE:-}" ]; then
    die "RP_ID is already '$current'. Changing it invalidates every registered passkey. Re-run with CONFIRM_RP_ID_CHANGE=1 if that is intended."
  fi

  var_set RP_ID "$id"
  var_set RP_ORIGIN "$origin"
  var_set RP_NAME "$name"

  echo "Wrote RP_ID, RP_ORIGIN and RP_NAME to $CONFIG."
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

main() {
  local cmd=${1:-}
  [ $# -gt 0 ] && shift
  case $cmd in
    get) cmd_get "$@" ;;
    set-vars) cmd_set_vars "$@" ;;
    set-secret) cmd_set_secret "$@" ;;
    -h | --help | help) usage 0 ;;
    *) usage ;;
  esac
}

main "$@"
