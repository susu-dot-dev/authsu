#!/usr/bin/env bash
# Reports hand-maintained pins that have fallen behind, for the weekly upkeep
# workflow (.github/workflows/upkeep.yml). Dependabot cannot update these:
#   - TinyGo and golangci-lint versions in tools.env
#   - the workers-go fork `replace` in go.mod
#
# Prints a markdown report on stdout and exits 0 when everything is current,
# 1 when something needs attention, 2 when a lookup itself failed (so a broken
# check is never mistaken for "all current").
#
# Needs: gh (authenticated; GH_TOKEN in CI), curl-free. Usage: scripts/check-upkeep.sh
set -uo pipefail
cd "$(dirname "$0")/.."

# shellcheck source=../tools.env
. ./tools.env

stale=0
failed=0
report=""

add() { report+="$1"$'\n'; }

# latest_tag OWNER/REPO -> prints the latest release tag, or fails.
latest_tag() { gh api "repos/$1/releases/latest" --jq .tag_name; }

check_tool() { # name pinned repo
  local name=$1 pinned=$2 repo=$3 latest
  if ! latest="$(latest_tag "$repo")" || [ -z "$latest" ]; then
    add "- :warning: could not look up the latest **$name** release ($repo)"
    failed=1
    return
  fi
  latest="${latest#v}"
  if [ "$latest" = "$pinned" ]; then
    add "- $name $pinned is current"
  else
    add "- **$name** is pinned at $pinned in \`tools.env\`; latest is $latest. Bump the version and its checksum together."
    stale=1
  fi
}

add "## Hand-maintained pins"
add ""
check_tool "TinyGo" "$TINYGO_VERSION" "tinygo-org/tinygo"
check_tool "golangci-lint" "$GOLANGCI_LINT_VERSION" "golangci/golangci-lint"

# The fork replace should go away once upstream releases what it carries.
if grep -q '^replace github.com/syumai/workers-go =>' go.mod; then
  fork="$(grep -o '=> [^ ]* [^ ]*' go.mod | head -n1 | sed 's/^=> //')"
  # The required upstream version, from either the one-line form
  # (`require mod vX`) or a block entry (`mod vX`).
  upstream_pinned="$(awk '
    $1 == "require" && $2 == "github.com/syumai/workers-go" { print $3; exit }
    $1 == "github.com/syumai/workers-go" && $2 ~ /^v/        { print $2; exit }' go.mod)"
  if latest="$(latest_tag syumai/workers-go)" && [ -n "$latest" ]; then
    if [ "$latest" != "$upstream_pinned" ]; then
      add "- **workers-go**: go.mod requires upstream $upstream_pinned but upstream's latest release is $latest, and go.mod replaces it with the fork \`$fork\`. Check whether the fork's changes are in $latest and drop the \`replace\` if so."
      stale=1
    else
      add "- workers-go: still replaced by the fork \`$fork\`; upstream has not released past $upstream_pinned"
    fi
  else
    add "- :warning: could not look up the latest **workers-go** release"
    failed=1
  fi
else
  add "- workers-go: no \`replace\` directive (using upstream)"
fi

printf '%s\n' "$report"
[ "$failed" -eq 0 ] || exit 2
[ "$stale" -eq 0 ] || exit 1
exit 0
