#!/bin/bash
# Run the MCP buyer end-to-end harness in a non-privileged container, under
# the container thermal guard. build.sh must have filled $E2E_WORKDIR/bin.
#
# Required environment:
#   E2E_WORKDIR   the run directory build.sh used; evidence lands here
#   TOS_SOURCE    tos checkout providing test/tostester
#   TOS_BUILD     tos build directory with the PQ genesis tools and validators
#   TOS_VENV      the tostester virtual environment (uv)
#   UV_PYTHON_DIR the uv-managed Python the venv links to; mounted read-only
#                 at the same path so the venv resolves
#   REGISTRY_CODE_BOC  Native Registry code BOC (base64) the tosctl build embeds
#   ACTOR_CODE_HASH    tvm-cell-sha256:<hex> pinned Service Actor release
# Optional: E2E_SKIP_REFUND=1 skips the hour-long timeout refund (quick
# iterations only; the evidence records it and an evidence run keeps it),
# E2E_CPUS (default 8).
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$here/../../.." && pwd)
: "${E2E_WORKDIR:?}" "${TOS_SOURCE:?}" "${TOS_BUILD:?}" "${TOS_VENV:?}" "${UV_PYTHON_DIR:?}" "${REGISTRY_CODE_BOC:?}" "${ACTOR_CODE_HASH:?}"
[ -f "$E2E_WORKDIR/build.json" ] || { echo "run build.sh first" >&2; exit 2; }
# The pinned base must still be what ubuntu:24.04 resolves to locally.
pinned=$(awk '/^FROM /{print $2; exit}' "$here/Dockerfile")
local_digest="ubuntu@$(docker image inspect ubuntu:24.04 --format '{{index .RepoDigests 0}}' | cut -d@ -f2)"
if [ "$pinned" != "$local_digest" ]; then
  echo "the Dockerfile's base $pinned is not the local ubuntu:24.04 ($local_digest)" >&2
  exit 2
fi
image="tos-mcp-buyer-e2e:$(sha256sum "$here/Dockerfile" | cut -c1-12)"
docker build --quiet --tag "$image" "$here" >/dev/null
name="mcp-buyer-e2e-$$"
network="$name-net"
# A private bridge with no route out and no published port: only the
# processes in the container reach the chain, the relay and the gateway.
docker network create --internal "$network" >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; docker network rm "$network" >/dev/null 2>&1 || true' EXIT
: > "$E2E_WORKDIR/thermal.jsonl"
docker run --detach --name "$name" --network "$network" --cpus "${E2E_CPUS:-8}" --pids-limit 4096 \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add FOWNER \
  --security-opt no-new-privileges \
  --mount "type=bind,src=$E2E_WORKDIR,dst=/e2e/work" \
  --mount "type=bind,src=$E2E_WORKDIR/bin,dst=/e2e-mounts/bin,readonly" \
  --mount "type=bind,src=$here/harness,dst=/e2e-mounts/harness,readonly" \
  --mount "type=bind,src=$repo/protocol/scripts,dst=/e2e-mounts/scripts,readonly" \
  --mount "type=bind,src=$TOS_SOURCE,dst=/e2e-mounts/tos-source,readonly" \
  --mount "type=bind,src=$TOS_BUILD,dst=/e2e-mounts/tos-build,readonly" \
  --mount "type=bind,src=$TOS_VENV,dst=/e2e-mounts/venv,readonly" \
  --mount "type=bind,src=$UV_PYTHON_DIR,dst=$UV_PYTHON_DIR,readonly" \
  --mount "type=bind,src=$REGISTRY_CODE_BOC,dst=/e2e-mounts/registry-code.boc,readonly" \
  --env "ACTOR_CODE_HASH=$ACTOR_CODE_HASH" --env "E2E_SKIP_REFUND=${E2E_SKIP_REFUND:-0}" \
  --env "HOST_UID=$(id -u)" --env "HOST_GID=$(id -g)" \
  --entrypoint /e2e-mounts/venv/bin/python3 "$image" -I /e2e-mounts/harness/run.py >/dev/null
"$here/container-thermal-guard.sh" "$name" "$E2E_WORKDIR/thermal.jsonl" &
guard=$!
status=$(docker wait "$name")
docker logs "$name" > "$E2E_WORKDIR/run.log" 2>&1 || true
wait "$guard" || true
# No artifact may hold the run's vault master key or any master_key value.
leaks=0
for artifact in "$E2E_WORKDIR"/run.log "$E2E_WORKDIR"/evidence.json "$E2E_WORKDIR"/transcript.jsonl; do
  [ -f "$artifact" ] || continue
  if grep -qE 'master_key=[0-9A-Fa-f]{8,}|VAULT_URL=' "$artifact"; then
    echo "secret found in $(basename "$artifact")" >&2
    leaks=1
  fi
done
tail -n 2 "$E2E_WORKDIR/run.log"
if [ "$status" = 0 ] && [ "$leaks" = 0 ]; then
  exit 0
fi
exit 1
