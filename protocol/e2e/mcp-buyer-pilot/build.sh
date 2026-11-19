#!/bin/bash
# Build or stage every binary of the agent-operated Gate D pilot into
# $PILOT_RUN/bin and write $PILOT_RUN/bin/build.json. Run it under setsid
# and the thermal guard.
#
# Required environment:
#   PILOT_RUN        owner-private run directory (created 0700)
#   OPENFOX_SOURCE   an OpenFox checkout; the provider is built from
#                    OPENFOX_COMMIT in a detached worktree of it
#   OPENFOX_COMMIT   the pinned OpenFox commit (full 40-hex SHA)
#   TOSCTL           the released tosctl-linux-x86_64
#   TOSCTL_SHA256    its SHA-256 as the release's SHA256SUMS lists it
#   CLAUDE_BINARY    the Claude Code CLI binary the buyer's model client runs
#   CODEX_BINARY     the Codex CLI binary the verifier's model client runs
# The ai tree must be clean at the commit it records: a dirty tree fails.
# The verifier does not use these binaries: it builds tos-service-verify
# itself from a fresh clone (run-verifier.py).
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$here/../../.." && pwd)
: "${PILOT_RUN:?}" "${OPENFOX_SOURCE:?}" "${OPENFOX_COMMIT:?}" "${TOSCTL:?}" "${TOSCTL_SHA256:?}"
: "${CLAUDE_BINARY:?}" "${CODEX_BINARY:?}"
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
mkdir -p "$PILOT_RUN" && chmod 700 "$PILOT_RUN"
bin="$PILOT_RUN/bin"
mkdir -p "$bin"
export GOWORK=off CGO_ENABLED=0
# The buyer's binaries, the local dress rehearsal's relay and code-hash
# helper, and tos-service-verify, which the harness uses only to observe a
# request's finalized state (it holds no key and sends nothing).
(cd "$repo" && go build -trimpath -o "$bin/" ./protocol/cmd/tos-service-buyer ./protocol/cmd/tos-service-buyer-mcp \
  ./protocol/cmd/tos-service-packet-relay ./protocol/cmd/service-actor-e2e-fixture ./protocol/cmd/tos-service-verify)
# OpenFox at the pinned commit, in a detached worktree removed afterwards.
openfox_tree="$PILOT_RUN/openfox-src"
git -C "$OPENFOX_SOURCE" worktree add --detach "$openfox_tree" "$OPENFOX_COMMIT" >/dev/null
trap 'git -C "$OPENFOX_SOURCE" worktree remove --force "$openfox_tree" >/dev/null 2>&1 || true' EXIT
if [ "$(git -C "$openfox_tree" rev-parse HEAD)" != "$OPENFOX_COMMIT" ]; then
  echo "the OpenFox worktree is not at OPENFOX_COMMIT" >&2
  exit 2
fi
(cd "$openfox_tree" && go build -trimpath -tags goolm,stdjson -o "$bin/openfox" ./cmd/openfox)
install -m 0755 "$TOSCTL" "$bin/tosctl"
install -m 0755 "$CLAUDE_BINARY" "$bin/claude"
install -m 0755 "$CODEX_BINARY" "$bin/codex"
chmod 0755 "$bin"/*
claude_version=$("$bin/claude" --version | head -n 1)
codex_version=$("$bin/codex" --version 2>/dev/null | tail -n 1)
python3 -I - "$bin" "$(git -C "$repo" rev-parse HEAD)" "$OPENFOX_COMMIT" "$TOSCTL_SHA256" \
  "$claude_version" "$codex_version" <<'EOF'
import hashlib, json, sys
from pathlib import Path
bin_dir, ai_commit, openfox_commit, tosctl_sha256, claude_version, codex_version = sys.argv[1:]
binaries = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(Path(bin_dir).iterdir()) if path.name != "build.json"}
build = {"ai_commit": ai_commit, "openfox_commit": openfox_commit, "tosctl_sha256": tosctl_sha256,
         "tosctl_source": "tos release v2026.11-1 tosctl-linux-x86_64", "claude_version": claude_version,
         "codex_version": codex_version, "binaries": binaries}
(Path(bin_dir) / "build.json").write_text(json.dumps(build, indent=2) + "\n")
EOF
echo "built into $bin"
