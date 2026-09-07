#!/usr/bin/env bash
#
# Watches the userspace helpers the VM's network depends on and takes the
# container down when one of them dies.
#
# Without this, a passt crash leaves QEMU attached to a socket nobody is
# answering: the guest keeps running with no network, health checks that only
# look at QEMU stay green, and the VM has to be noticed and restarted by hand.
# Terminating PID 1 instead turns that into a normal container restart, which
# `restart: always` recovers from on its own.
#
# Usage: watchdog.sh <name> <pidfile> <logfile> [<name> <pidfile> <logfile>...]

set -Eeuo pipefail

: "${QEMU_DIR:=/run/shm}"
: "${WATCHDOG_INTERVAL:=5}"
: "${WATCHDOG_TAIL:=50}"

QEMU_END="$QEMU_DIR/qemu.end"

log() { echo "❯ [watchdog] $*"; }

# resolve turns a pid file into a live PID, waiting for helpers that write their
# pid file slightly after being started.
resolve() {

  local pidfile="$1" deadline=$((SECONDS + 120)) pid=""

  while (( SECONDS < deadline )); do
    [ -f "$QEMU_END" ] && return 1
    if [ -s "$pidfile" ]; then
      pid=$(tr -dc '0-9' < "$pidfile" 2>/dev/null || true)
      if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "$pid"
        return 0
      fi
    fi
    sleep 1
  done

  return 1
}

names=()
pidfiles=()
logfiles=()
pids=()

while (( $# >= 3 )); do
  names+=( "$1" )
  pidfiles+=( "$2" )
  logfiles+=( "$3" )
  shift 3
done

if (( ${#names[@]} == 0 )); then
  log "nothing to watch, exiting."
  exit 0
fi

for i in "${!names[@]}"; do
  if ! pid=$(resolve "${pidfiles[$i]}"); then
    # The container is already shutting down, or the helper never came up — in
    # which case the startup scripts have already reported the real error.
    log "${names[$i]} did not report a PID, not watching it."
    pids+=( "" )
    continue
  fi
  pids+=( "$pid" )
  log "watching ${names[$i]} (pid $pid)"
done

while :; do

  sleep "$WATCHDOG_INTERVAL"

  # A shutdown that the container initiated is not a failure.
  [ -f "$QEMU_END" ] && exit 0

  for i in "${!names[@]}"; do

    pid="${pids[$i]}"
    [ -z "$pid" ] && continue
    kill -0 "$pid" 2>/dev/null && continue

    # Re-check the shutdown marker: the helpers are killed as part of a normal
    # shutdown and the marker may have appeared during this pass.
    [ -f "$QEMU_END" ] && exit 0

    log "${names[$i]} (pid $pid) died."

    if [ -n "${logfiles[$i]}" ] && [ -s "${logfiles[$i]}" ]; then
      log "last ${WATCHDOG_TAIL} lines of ${logfiles[$i]}:"
      tail -n "${WATCHDOG_TAIL}" "${logfiles[$i]}" 2>/dev/null || true
    fi

    log "stopping the container so it can be restarted with working networking."
    kill -TERM 1 2>/dev/null || true
    exit 1
  done

done
