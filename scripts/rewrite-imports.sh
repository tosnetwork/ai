#!/bin/sh
# Rewrites the former module paths of the imported components to their
# package paths in this repository. The rewrite is a pure prefix substitution
# (Go import lines only, then gofmt);
# see scripts/rewrite_imports.py for the file set and the hash-pinned paths it
# never touches. Run from anywhere; it operates on the tracked files of the
# repository containing this script.
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec python3 -I "$repo/scripts/rewrite_imports.py" "$repo" "$@"
