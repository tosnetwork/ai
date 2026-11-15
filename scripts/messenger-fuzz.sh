#!/bin/sh
# Runs every native Fuzz target of each package for a fixed number of
# executions. A count-bounded run stops on the count, with no deadline that
# the fuzz coordinator could observe before its worker (see FUZZ_EXECUTIONS in
# the Makefile). A package that lists no fuzz target is an error, so a renamed
# target cannot silently drop out.
#
# usage: messenger-fuzz.sh <executions> <package>...
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"
executions=$1
shift
for package in "$@"; do
  targets=$(go test "$package" -list 'Fuzz.*' | grep '^Fuzz' || true)
  if [ -z "$targets" ]; then
    echo "$package lists no fuzz target" >&2
    exit 1
  fi
  for target in $targets; do
    echo "== $package $target"
    go test "$package" -run "^${target}\$" -fuzz "^${target}\$" -fuzztime="${executions}x"
  done
done
