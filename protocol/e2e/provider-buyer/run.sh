#!/bin/bash
# Run the provider-buyer end-to-end harness: protocol/e2e/mcp-buyer's
# container, mounts, thermal guard and secret scan, with this directory's
# harness, whose provider is tos-service-provider. build.sh (this
# directory's) must have filled $E2E_WORKDIR/bin.
#
# Required environment: as protocol/e2e/mcp-buyer/run.sh (E2E_WORKDIR,
# TOS_SOURCE, TOS_BUILD, TOS_VENV, REGISTRY_CODE_BOC, ACTOR_CODE_HASH).
# With ACTOR_CODE_HASH the test-only Service Actor build's hash, the offer
# uses that build's 600 s windows and the refund scenario runs in about
# twenty minutes; with the release hash it waits out the hour-long windows.
# E2E_SKIP_REFUND=1 skips the refund scenario (the evidence records it).
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
E2E_HARNESS_DIR="$here/harness" exec "$here/../mcp-buyer/run.sh"
