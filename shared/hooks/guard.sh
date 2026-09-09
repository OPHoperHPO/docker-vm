#!/usr/bin/env bash
#
# Attaches vmguard to the guest's network and starts the helper watchdog.
#
# passt listens on a unix socket and QEMU connects to it. vmguard is inserted
# between the two: it creates its own socket, QEMU is pointed at that instead,
# and vmguard forwards frames to passt only when the configured policy allows
# them. Nothing inside the guest can observe or bypass this, and it needs no
# additional container capabilities.
#
# Sourced from /run/network.sh after the upstream network setup has run.

set -Eeuo pipefail

: "${NET_GUARD:="auto"}"            # auto | Y | N
: "${NET_WATCHDOG:="Y"}"            # restart the container if passt dies
: "${VMGUARD:="/usr/local/bin/vmguard"}"

VMGUARD_PID="$QEMU_DIR/vmguard.pid"
VMGUARD_SOCKET="$QEMU_DIR/vmguard.sock"

# guardConfigured reports whether any access rule was supplied. It is what makes
# NET_GUARD=auto do the right thing: no rules, no interposition.
guardConfigured() {

  local var value

  for var in NET_ALLOW NET_DENY NET_RULES NET_RULES_FILE NET_POLICY \
             NET_ALLOW_IN NET_DENY_IN NET_RULES_IN NET_POLICY_IN \
             NET_BLOCK_PRIVATE NET_GUARD_HTTP; do
    value=$(strip "${!var:-}")
    [ -n "$value" ] && return 0
  done

  value=$(strip "${NET_PRESET:-}")
  case "${value,,}" in
    "" | "open" | "none" | "off" ) ;;
    * ) return 0 ;;
  esac

  return 1
}

guardWanted() {

  disabled "$NET_GUARD" && return 1
  enabled "$NET_GUARD" && return 0
  guardConfigured

}

# guardGateway reports the address the guest sees as its gateway, which the
# 'gateway' rule alias and the ICMP rejections both need.
guardGateway() {

  local file="$QEMU_DIR/qemu.gw"

  if [ -s "$file" ]; then
    tr -d '[:space:]' < "$file"
    return 0
  fi

  # Fall back to passt's own convention of using .1 in the guest's subnet.
  [ -n "${IP:-}" ] && [[ "$IP" == *.* ]] && echo "${IP%.*}.1"
  return 0
}

startGuard() {

  local gateway
  gateway=$(guardGateway)

  if [ ! -x "$VMGUARD" ]; then
    error "Network rules are configured but $VMGUARD is missing from this image!"
    return 1
  fi

  # Reject an unusable policy before QEMU starts, so a typo in compose surfaces
  # as a clear startup error instead of a guest that silently loses its network.
  if ! "$VMGUARD" -check -gateway "$gateway" -guest "${IP:-}"; then
    error "The network rules are invalid, refusing to start."
    return 1
  fi

  rm -f "$VMGUARD_SOCKET"

  "$VMGUARD" \
    -listen "$VMGUARD_SOCKET" \
    -upstream "$PASST_SOCKET" \
    -gateway "$gateway" \
    -guest "${IP:-}" &

  local pid=$!
  echo "$pid" > "$VMGUARD_PID"

  # Wait for the socket QEMU is about to be pointed at.
  local deadline=$((SECONDS + 15))
  while [ ! -S "$VMGUARD_SOCKET" ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      error "vmguard exited during startup."
      rm -f "$VMGUARD_PID"
      return 1
    fi
    if (( SECONDS >= deadline )); then
      error "vmguard did not create $VMGUARD_SOCKET within 15 seconds."
      pKill "$pid"
      rm -f "$VMGUARD_PID"
      return 1
    fi
    sleep 0.2
  done

  # Point QEMU at vmguard instead of passt.
  local before="$NET_OPTS"
  NET_OPTS="${NET_OPTS//addr.path=$PASST_SOCKET/addr.path=$VMGUARD_SOCKET}"

  if [[ "$NET_OPTS" == "$before" ]]; then
    error "Could not attach vmguard: unexpected netdev options \"$NET_OPTS\"."
    pKill "$pid"
    rm -f "$VMGUARD_PID"
    return 1
  fi

  # Terminate it with the other helpers during a normal shutdown.
  HELPER_PIDS+=( VMGUARD_PID )

  info "Network access rules are active (vmguard)."
  return 0
}

startWatchdog() {

  disabled "$NET_WATCHDOG" && return 0
  [ ! -x /run/watchdog.sh ] && return 0

  local targets=()

  if [[ "${NETWORK,,}" == "passt" ]] && [ -s "$PASST_PID" ]; then
    targets+=( passt "$PASST_PID" /var/log/passt.log )
  fi

  if [ -s "$VMGUARD_PID" ]; then
    # vmguard logs to the container's stdout, so there is no file to tail.
    targets+=( vmguard "$VMGUARD_PID" "" )
  fi

  (( ${#targets[@]} == 0 )) && return 0

  QEMU_DIR="$QEMU_DIR" /run/watchdog.sh "${targets[@]}" &

  return 0
}

# A passt that fails to start is invisible from the outside: the base image
# falls back to slirp, the VM boots, and only the forwarded ports and the
# missing policy socket differ. Say it out loud even when no rules were asked
# for, so the next person does not debug a working-looking VM.
guardRequested="${VM_NETWORK_REQUESTED:-}"
if [[ "${guardRequested,,}" == "passt" && "${NETWORK,,}" == "slirp" ]]; then
  warn "passt was requested but did not start; the container fell back to slirp."
  warn "Forwarded ports and throughput differ, and access rules cannot be enforced."
  warn "passt's own reason is in the lines above."
fi

if guardWanted; then

  if disabled "$NETWORK"; then

    # Networking is off entirely, which is stricter than any rule set.
    info "Networking is disabled; the access rules have nothing to filter."

  elif [[ "${NETWORK,,}" != "passt" ]]; then
    error "Network access rules require NETWORK=passt, but the active mode is \"$NETWORK\"."
    if [[ "${NETWORK,,}" == "slirp" ]]; then
      error "passt failed to start and the container fell back to slirp; the log above says why."
    fi
    error "Refusing to start the VM without the requested restrictions."
    exit 25

  else

    startGuard || exit 25

  fi

fi

startWatchdog

return 0
