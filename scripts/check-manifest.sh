#!/usr/bin/env sh
# Fails when the bundled adapter manifest differs from the one the auth API
# publishes. The bundled copy is what the adapter serves whenever the live fetch
# fails, so a route missing from it answers 404 in that case. apiVersion is
# ignored: it changes on every API release, routes do not.
#
#   scripts/check-manifest.sh [source]
#
# source defaults to seamless-auth-api main. Fix a failure with
# scripts/sync-manifest.sh.
set -eu

source="${1:-https://raw.githubusercontent.com/fells-code/seamless-auth-api/main/adapter-manifest.json}"
bundled="$(dirname "$0")/../manifest.json"

dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT

case "$source" in
  http://*|https://*) curl -fsSL "$source" -o "$dir/upstream.json" ;;
  *) cp "$source" "$dir/upstream.json" ;;
esac

normalize() { jq -S 'del(.apiVersion) | .routes |= sort_by(.path, .method)' "$1"; }
normalize "$bundled" > "$dir/bundled.norm"
normalize "$dir/upstream.json" > "$dir/upstream.norm"

if cmp -s "$dir/bundled.norm" "$dir/upstream.norm"; then
  echo "Bundled manifest matches $source"
  exit 0
fi

routes() { jq -r '.routes[] | "\(.method) \(.path)"' "$1" | sort; }
routes "$bundled" > "$dir/bundled.routes"
routes "$dir/upstream.json" > "$dir/upstream.routes"

echo "Bundled manifest (manifest.json) differs from $source" >&2
echo "Missing from the bundled copy:" >&2
comm -13 "$dir/bundled.routes" "$dir/upstream.routes" | sed 's/^/  /' >&2
echo "Only in the bundled copy:" >&2
comm -23 "$dir/bundled.routes" "$dir/upstream.routes" | sed 's/^/  /' >&2
echo "Full difference:" >&2
diff -u "$dir/bundled.norm" "$dir/upstream.norm" >&2 || true
echo "Run scripts/sync-manifest.sh to update it." >&2
exit 1
