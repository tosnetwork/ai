#!/bin/sh
# Component boundaries: gateway/ must not depend on execution/; protocol/
# must depend on neither gateway/ nor execution/; messenger/ may depend on
# protocol/ only; and no component depends on messenger/.
#
# The package graph is followed transitively, test-only imports included, for
# the host platform and for every other platform the tree has build-tagged
# files for (windows, darwin), so a file the host build skips cannot hide a
# forbidden import. A textual scan of every Go file, whatever its build
# constraints, is the backstop for tags no pass selects.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
module=github.com/tosnetwork/ai
cd "$repo"
status=0

graph() {
  platform=$1
  component=$2
  shift 2
  goos=$(go env GOOS)
  [ "$platform" = host ] || goos=$platform
  # -e keeps going past packages that have no files for this platform; any
  # other load error fails the check instead of hiding dependencies.
  listing=$(GOOS=$goos go list -e -deps -test \
    -f '{{.ImportPath}}{{with .Error}} LOAD-ERROR {{.Err}}{{end}}' "./$component/...") || {
    status=1
    echo "boundary check ($platform): go list failed for $component/" >&2
    return
  }
  errors=$(printf '%s\n' "$listing" | grep ' LOAD-ERROR ' | grep -v 'build constraints exclude all Go files' || true)
  if [ -n "$errors" ]; then
    status=1
    echo "boundary check ($platform): $component/ does not load:" >&2
    printf '%s\n' "$errors" | sed 's/^/  /' >&2
  fi
  for forbidden in "$@"; do
    found=$(printf '%s\n' "$listing" | cut -d' ' -f1 | grep -E "^$module/$forbidden(/|$)" || true)
    if [ -n "$found" ]; then
      status=1
      echo "boundary violation ($platform): $component/ depends on $forbidden/:" >&2
      printf '%s\n' "$found" | sed 's/^/  reaches /' >&2
    fi
  done
}

text() {
  component=$1
  shift
  for forbidden in "$@"; do
    found=$(find "$component" -name '*.go' -type f -exec grep -nHE \
      "^[[:space:]]*(import[[:space:]]+)?([A-Za-z_.][A-Za-z0-9_]*[[:space:]]+)?\"$module/$forbidden(/[^\"]*)?\"" {} + || true)
    if [ -n "$found" ]; then
      status=1
      echo "boundary violation (source text): $component/ imports $forbidden/:" >&2
      printf '%s\n' "$found" | sed 's/^/  /' >&2
    fi
  done
}

for platform in host windows darwin; do
  graph "$platform" gateway execution messenger
  graph "$platform" protocol gateway execution messenger
  graph "$platform" execution messenger
  graph "$platform" messenger gateway execution
done
text gateway execution messenger
text protocol gateway execution messenger
text execution messenger
text messenger gateway execution

if [ "$status" = 0 ]; then
  echo "boundaries hold (host, windows, darwin, source text): gateway/ does not depend on execution/; protocol/ depends on neither; messenger/ depends on protocol/ only; nothing depends on messenger/"
fi
exit "$status"
