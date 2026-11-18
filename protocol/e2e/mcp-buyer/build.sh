#!/bin/bash
# Build every binary the MCP buyer end-to-end harness runs, on the host,
# into $E2E_WORKDIR/bin. Run it under setsid and the thermal guard.
#
# Required environment:
#   E2E_WORKDIR      owner-private run directory (created 0700)
#   OPENFOX_SOURCE   an OpenFox checkout; the provider is built from
#                    OPENFOX_COMMIT in a detached worktree of it
#   OPENFOX_COMMIT   the pinned OpenFox commit (full 40-hex SHA)
#   TOSCTL           the pinned tosctl binary
#   TOSCTL_SHA256    its lowercase hex SHA-256
# The ai tree must be clean at the commit it records: a dirty tree fails.
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$here/../../.." && pwd)
: "${E2E_WORKDIR:?}" "${OPENFOX_SOURCE:?}" "${OPENFOX_COMMIT:?}" "${TOSCTL:?}" "${TOSCTL_SHA256:?}"
if ! [[ "$OPENFOX_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "OPENFOX_COMMIT must be a full 40-hex commit" >&2
  exit 2
fi
if [ -n "$(git -C "$repo" status --porcelain)" ]; then
  echo "the ai tree is not clean; commit before an evidence build" >&2
  exit 2
fi
if [ "$(sha256sum "$TOSCTL" | cut -d' ' -f1)" != "$TOSCTL_SHA256" ]; then
  echo "tosctl does not match TOSCTL_SHA256" >&2
  exit 2
fi
mkdir -p "$E2E_WORKDIR" && chmod 700 "$E2E_WORKDIR"
bin="$E2E_WORKDIR/bin"
mkdir -p "$bin"
export GOWORK=off CGO_ENABLED=0
(cd "$repo" && go build -trimpath -o "$bin/" ./protocol/cmd/tos-service-buyer ./protocol/cmd/tos-service-buyer-mcp \
  ./protocol/cmd/mcp-buyer-e2e-client ./protocol/cmd/tos-service-packet-relay ./protocol/cmd/service-actor-e2e-fixture)
(cd "$repo" && go build -trimpath -o "$bin/tos-service-gateway" ./gateway/cmd/api)
# The test-only stand-in executor exists only under its build tag; its own
# tests run first.
(cd "$repo" && go test -count=1 -tags e2eexec ./execution/cmd/software-work-executord-e2e &&
  go build -trimpath -tags e2eexec -o "$bin/software-work-executord-e2e" ./execution/cmd/software-work-executord-e2e)
# OpenFox at the pinned commit, in a detached worktree removed afterwards.
openfox_tree="$E2E_WORKDIR/openfox-src"
git -C "$OPENFOX_SOURCE" worktree add --detach "$openfox_tree" "$OPENFOX_COMMIT" >/dev/null
trap 'git -C "$OPENFOX_SOURCE" worktree remove --force "$openfox_tree" >/dev/null 2>&1 || true' EXIT
if [ "$(git -C "$openfox_tree" rev-parse HEAD)" != "$OPENFOX_COMMIT" ]; then
  echo "the OpenFox worktree is not at OPENFOX_COMMIT" >&2
  exit 2
fi
# OpenFox's own release tags: the pure-Go Olm and the standard JSON codec.
(cd "$openfox_tree" && go build -trimpath -tags goolm,stdjson -o "$bin/openfox" ./cmd/openfox)
install -m 0755 "$TOSCTL" "$bin/tosctl"
chmod 0755 "$bin"/*
# The record of what was built.
{
  printf '{"ai_commit":"%s",' "$(git -C "$repo" rev-parse HEAD)"
  printf '"openfox_commit":"%s",' "$OPENFOX_COMMIT"
  printf '"tosctl_sha256":"%s",' "$TOSCTL_SHA256"
  printf '"binaries":{'
  first=1
  for file in "$bin"/*; do
    [ "$first" = 1 ] || printf ','
    first=0
    printf '"%s":"%s"' "$(basename "$file")" "$(sha256sum "$file" | cut -d' ' -f1)"
  done
  printf '}}\n'
} > "$E2E_WORKDIR/build.json"
echo "built into $bin"
