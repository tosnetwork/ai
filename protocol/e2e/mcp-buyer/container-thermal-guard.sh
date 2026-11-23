#!/bin/bash
# Thermal guard for the containerised harness: the same decision as the
# host guard (pause while a CPU package is at or above 90 C, resume under
# 85 C), applied as `docker pause` / `docker unpause`, a cgroup freeze of
# every process in the container. A freeze stops all three validators
# together, so consensus resumes where it stopped.
#
# Usage: container-thermal-guard.sh CONTAINER PAUSE_LOG
# Every pause and resume is appended to PAUSE_LOG as one JSON line, which
# run.sh copies into the evidence. PAUSE_LOG may be a /dev/fd/N path the
# caller opened. A line that cannot be written is reported on standard error
# and makes the guard exit 1 when it ends, so a pause is never unrecorded
# silently.
set -u
container=$1
log=$2
paused=0
failed=0
running() { [ "$(docker inspect --format '{{.State.Running}}' "$container" 2>/dev/null)" = true ]; }
note() {
  if ! printf '{"event":"%s","celsius":%d,"utc":"%s"}\n' "$1" "$2" "$(date -u +%FT%TZ)" >> "$log"; then
    failed=1
    echo "thermal guard: could not record a $1 at $2 C" >&2
  fi
}
# Wait for the container to start, at most 60 s.
for _ in $(seq 60); do running && break; sleep 1; done
while running || [ "$paused" = 1 ]; do
  t=$(sensors 2>/dev/null | awk '/^Package id/ {gsub(/[+°C]/,"",$4); if ($4>m) m=$4} END {print int(m)}')
  if [ "$paused" = 0 ] && [ "${t:-0}" -ge 90 ]; then
    if docker pause "$container" >/dev/null 2>&1; then
      paused=1
      note pause "${t:-0}"
    fi
  fi
  if [ "$paused" = 1 ] && [ "${t:-0}" -lt 85 ]; then
    if docker unpause "$container" >/dev/null 2>&1; then
      paused=0
      note resume "${t:-0}"
    fi
  fi
  # A paused container reports Running; once it stops, the loop ends.
  running || break
  sleep 1
done
exit "$failed"
