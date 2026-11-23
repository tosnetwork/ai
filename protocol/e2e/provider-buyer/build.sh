#!/bin/bash
# Build every binary the provider-buyer end-to-end harness runs, on the host,
# into $E2E_WORKDIR/bin: the buyer side of protocol/e2e/mcp-buyer and, as
# the provider, this repository's tos-service-provider. Nothing is built
# from another repository. Run it under setsid and the thermal guard.
#
# Required environment:
#   E2E_WORKDIR      owner-private run directory (created 0700)
#   TOSCTL           the pinned tosctl binary
#   TOSCTL_SHA256    its lowercase hex SHA-256
# The ai tree must be clean at the commit it records: a dirty tree fails.
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$here/../../.." && pwd)
: "${E2E_WORKDIR:?}" "${TOSCTL:?}" "${TOSCTL_SHA256:?}"
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
  ./protocol/cmd/mcp-buyer-e2e-client ./protocol/cmd/tos-service-packet-relay ./protocol/cmd/service-actor-e2e-fixture \
  ./protocol/cmd/tos-service-rpc ./provider/cmd/tos-service-provider)
(cd "$repo" && go build -trimpath -o "$bin/tos-service-gateway" ./gateway/cmd/api)
# The test-only stand-in executor exists only under its build tag; its own
# tests run first.
(cd "$repo" && go test -count=1 -tags e2eexec ./execution/cmd/software-work-executord-e2e &&
  go build -trimpath -tags e2eexec -o "$bin/software-work-executord-e2e" ./execution/cmd/software-work-executord-e2e)
install -m 0755 "$TOSCTL" "$bin/tosctl"
chmod 0755 "$bin"/*
# The record of what was built.
{
  printf '{"ai_commit":"%s",' "$(git -C "$repo" rev-parse HEAD)"
  printf '"provider":"tos-service-provider",'
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
