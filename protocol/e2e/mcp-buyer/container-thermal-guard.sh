#!/bin/bash
# Thermal guard for the containerised harness: the same decision as the
# host guard (pause while a CPU package is at or above 90 C, resume under
# 85 C), applied as `docker pause` / `docker unpause`, a cgroup freeze of
# every process in the container. A freeze stops all three validators
# together, so consensus resumes where it stopped.
#
# Usage: container-thermal-guard.sh CONTAINER PAUSE_LOG
# Every pause and resume is appended to PAUSE_LOG as one JSON line, which
# run.sh copies into the evidence.
set -u
container=$1
log=$2
paused=0
running() { [ "$(docker inspect --format '{{.State.Running}}' "$container" 2>/dev/null)" = true ]; }
# Wait for the container to start, at most 60 s.
for _ in $(seq 60); do running && break; sleep 1; done
while running || [ "$paused" = 1 ]; do
  t=$(sensors 2>/dev/null | awk '/^Package id/ {gsub(/[+°C]/,"",$4); if ($4>m) m=$4} END {print int(m)}')
  if [ "$paused" = 0 ] && [ "${t:-0}" -ge 90 ]; then
    if docker pause "$container" >/dev/null 2>&1; then
      paused=1
      printf '{"event":"pause","celsius":%d,"utc":"%s"}\n' "${t:-0}" "$(date -u +%FT%TZ)" >> "$log"
    fi
  fi
  if [ "$paused" = 1 ] && [ "${t:-0}" -lt 85 ]; then
    if docker unpause "$container" >/dev/null 2>&1; then
      paused=0
      printf '{"event":"resume","celsius":%d,"utc":"%s"}\n' "${t:-0}" "$(date -u +%FT%TZ)" >> "$log"
    fi
  fi
  # A paused container reports Running; once it stops, the loop ends.
  running || break
  sleep 1
done
