#!/bin/sh
# Component boundaries: gateway/ must not depend on execution/, and protocol/
# must depend on neither gateway/ nor execution/. Dependencies are followed
# transitively and include test-only imports.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
module=github.com/tosnetwork/ai
cd "$repo"
status=0

check() {
  component=$1
  shift
  for forbidden in "$@"; do
    found=$(go list -deps -test "./$component/..." | grep -E "^$module/$forbidden(/|$)" || true)
    if [ -n "$found" ]; then
      status=1
      echo "boundary violation: $component/ depends on $forbidden/:" >&2
      go list -test -f '{{.ImportPath}}{{range .Imports}} {{.}}{{end}}{{range .TestImports}} {{.}}{{end}}{{range .XTestImports}} {{.}}{{end}}' "./$component/..." |
        awk -v prefix="$module/$forbidden" '{ for (i = 2; i <= NF; i++) if ($i == prefix || index($i, prefix "/") == 1) print "  " $1 " imports " $i }' |
        sort -u >&2
      printf '%s\n' "$found" | sed 's/^/  reaches /' >&2
    fi
  done
}

check gateway execution
check protocol gateway execution

if [ "$status" = 0 ]; then
  echo "boundaries hold: gateway/ does not depend on execution/; protocol/ depends on neither"
fi
exit "$status"
