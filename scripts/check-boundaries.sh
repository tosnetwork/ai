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

# No Go file may use //go:linkname. It reaches unexported identifiers of
# another package, so it would let code outside a package reassign a test-only
# seam such as the Guarantor verifier variables, which the package's own guard
# tests can only check within the package.
linkname=$(find . -name '*.go' -type f -not -path './.git/*' -exec grep -nH '//go:linkname' {} + || true)
if [ -n "$linkname" ]; then
  status=1
  echo "boundary violation: //go:linkname is not allowed:" >&2
  printf '%s\n' "$linkname" | sed 's/^/  /' >&2
fi

# Every Go file is a regular file. The scans in this script read regular files
# only, while the go command also compiles a symbolic link to one, so a link
# named like a Go file would bring an unscanned file into a package.
links=$(find . -name '*.go' -type l -not -path './.git/*' || true)
if [ -n "$links" ]; then
  status=1
  echo "boundary violation: a Go file is a symbolic link:" >&2
  printf '%s\n' "$links" | sed 's/^/  /' >&2
fi

# No Go package directory holds assembly, C or prebuilt object files. The go
# command builds them into the package beside its Go files, and no check here
# or in a package's own guard tests reads them. The Rust driver's tree under
# messenger/rust/ is exempt, and must therefore hold no Go file.
foreign=$(find . \( -name '*.s' -o -name '*.S' -o -name '*.sx' -o -name '*.c' -o -name '*.syso' \) \
  -not -path './.git/*' -not -path './messenger/rust/*' | while IFS= read -r file; do
  for sibling in "$(dirname -- "$file")"/*.go; do
    if [ -e "$sibling" ] || [ -L "$sibling" ]; then
      printf '%s\n' "$file"
      break
    fi
  done
done)
if [ -n "$foreign" ]; then
  status=1
  echo "boundary violation: a Go package directory holds assembly, C or object files:" >&2
  printf '%s\n' "$foreign" | sed 's/^/  /' >&2
fi
driver=$(find messenger/rust -name '*.go' || true)
if [ -n "$driver" ]; then
  status=1
  echo "boundary violation: the Rust driver tree, exempt from the assembly, C and object file check, holds Go files:" >&2
  printf '%s\n' "$driver" | sed 's/^/  /' >&2
fi

# The Guarantor package's non-test files import neither unsafe nor C. Either
# reaches memory and symbols past the type system, and so past the unexported
# verifier seams that the package's guard tests check by syntax. The loaded
# package is checked on each platform; the source text of every non-test
# file, whatever its build constraints, is the backstop.
guarantor=protocol/pkg/agentguarantor
for platform in host windows darwin; do
  goos=$(go env GOOS)
  [ "$platform" = host ] || goos=$platform
  loaded=$(GOOS=$goos go list -e \
    -f '{{range .Imports}}import {{.}}{{"\n"}}{{end}}{{range .CgoFiles}}cgo file {{.}}{{"\n"}}{{end}}{{with .Error}}LOAD-ERROR {{.Err}}{{end}}' \
    "./$guarantor") || {
    status=1
    echo "boundary check ($platform): go list failed for $guarantor" >&2
    continue
  }
  found=$(printf '%s\n' "$loaded" | grep -E '^(import (unsafe|C)$|cgo file |LOAD-ERROR )' || true)
  if [ -n "$found" ]; then
    status=1
    echo "boundary violation ($platform): $guarantor uses unsafe or cgo in a non-test file, or does not load:" >&2
    printf '%s\n' "$found" | sed 's/^/  /' >&2
  fi
done
unsafe=$(find "$guarantor" -name '*.go' -not -name '*_test.go' -exec grep -nHE '["`](unsafe|C)["`]' {} + || true)
if [ -n "$unsafe" ]; then
  status=1
  echo "boundary violation (source text): $guarantor names unsafe or C in a non-test file:" >&2
  printf '%s\n' "$unsafe" | sed 's/^/  /' >&2
fi

if [ "$status" = 0 ]; then
  echo "boundaries hold (host, windows, darwin, source text): gateway/ does not depend on execution/; protocol/ depends on neither; messenger/ depends on protocol/ only; nothing depends on messenger/; no //go:linkname; no symlinked Go file; no assembly, C or object file in a Go package directory; no unsafe or cgo in $guarantor"
fi
exit "$status"
