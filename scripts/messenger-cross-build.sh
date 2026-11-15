#!/bin/sh
# Builds every messenger/ package for each <goos>/<goarch> argument.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"
for target in "$@"; do
  echo "== $target"
  GOOS=${target%/*} GOARCH=${target#*/} go build ./messenger/...
done
