#!/usr/bin/env sh
# Refreshes the adapter manifest embedded in this crate from the auth API.
# The adapter fetches the live manifest at runtime and only falls back to this
# copy, so it only has to be as new as the oldest API it supports.
#
#   scripts/sync-manifest.sh [path-or-url]
set -eu

source="${1:-https://raw.githubusercontent.com/fells-code/seamless-auth-api/main/adapter-manifest.json}"
target="$(dirname "$0")/../manifest.json"

case "$source" in
  http://*|https://*) curl -fsSL "$source" -o "$target.tmp" ;;
  *) cp "$source" "$target.tmp" ;;
esac

grep -q '"schemaVersion": *1' "$target.tmp" || { rm -f "$target.tmp"; echo "$source is not a schemaVersion 1 manifest" >&2; exit 1; }
mv "$target.tmp" "$target"
echo "Wrote $target"
