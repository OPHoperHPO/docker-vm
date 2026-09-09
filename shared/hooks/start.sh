#!/usr/bin/env bash
#
# Startup hook, sourced by /run/entry.sh before any of the image's own scripts.
#
# It exists to fix the two things that made long-running VMs restart in a loop
# when the container was left to its defaults, and to give per-image hooks a
# place to run:
#
#   * the open-file limit, which passt needs raised before it starts
#   * image-specific setup, from /run/hooks.d
#
# The helper functions from utils.sh do not exist yet at this point, so this
# file only uses plain shell builtins and echo.

set -Eeuo pipefail

vmLog() { echo "❯ $*"; }
vmWarn() { echo "❯ Warning: $*" >&2; }

# raiseFileLimit lifts the soft descriptor limit to the hard one.
#
# passt sizes its flow table from RLIMIT_NOFILE and needs thousands of
# descriptors for a busy guest; Docker still starts containers with a soft limit
# of 1024, which makes passt fail or die once a guest opens enough connections.
# Every process started from here — passt, vmguard and QEMU itself — inherits
# the raised limit, so no ulimits block is needed in compose for the common case.
raiseFileLimit() {

  local soft hard target="${NOFILE_LIMIT:-1048576}"

  soft=$(ulimit -Sn 2>/dev/null || echo 0)
  hard=$(ulimit -Hn 2>/dev/null || echo 0)

  [[ "$soft" == "unlimited" ]] && return 0

  if [[ "$hard" != "unlimited" ]] && (( hard < target )); then
    target="$hard"
  fi

  if (( soft >= target )); then
    return 0
  fi

  if ! ulimit -n "$target" 2>/dev/null; then
    vmWarn "could not raise the open-file limit above $soft."
    return 0
  fi

  vmLog "Raised the open-file limit from $soft to $target."

  if (( target < 65536 )); then
    vmWarn "the open-file limit is only $target, which passt may exhaust."
    vmWarn "Raise it on the container, for example with:"
    vmWarn "  ulimits: { nofile: { soft: 1048576, hard: 1048576 } }"
  fi

  return 0
}

raiseFileLimit

# The mode the operator asked for, before /run/network.sh gets a chance to fall
# back to another one. guard.sh compares the two to notice a silent downgrade.
# shellcheck disable=SC2034  # read by guard.sh, sourced later in the same shell
VM_NETWORK_REQUESTED="${NETWORK:-}"

# warnPasstPortBudget explains "Couldn't listen on requested ports" before it
# happens.
#
# passt binds one socket per forwarded port, and "all" is roughly 32k of them
# per protocol. Below that many descriptors passt exits with a message that says
# nothing about descriptors, and the container falls back to slirp. The limit is
# already known here, so compare and say so while the number can still be fixed.
warnPasstPortBudget() {

  local opts="$1" protocols=0 needed soft

  [[ "$opts" == *"-t all"* || "$opts" == *"--tcp-ports all"* ]] && (( protocols++ )) || :
  [[ "$opts" == *"-u all"* || "$opts" == *"--udp-ports all"* ]] && (( protocols++ )) || :
  (( protocols == 0 )) && return 0

  soft=$(ulimit -Sn 2>/dev/null || echo 0)
  [[ "$soft" == "unlimited" ]] && return 0

  needed=$(( protocols * 32767 + 8192 ))
  (( soft >= needed )) && return 0

  vmWarn "PASST_OPTS forwards all ports, which needs about $needed open files, but"
  vmWarn "the limit here is $soft. passt will fail with \"Couldn't listen on requested"
  vmWarn "ports\" and the container will fall back to slirp. Raise the limit with"
  vmWarn "  ulimits: { nofile: { soft: 1048576, hard: 1048576 } }"
  vmWarn "or forward only the ports you need with USER_PORTS."

  return 0
}

# reconcilePasstPorts keeps PASST_OPTS and the image's own port forwarding from
# describing the same port twice.
#
# /run/network.sh always appends a forwarding list of its own to PASST_OPTS: the
# built-in default (22, or 3389 for Windows) plus USER_PORTS. passt refuses two
# rules that overlap — it prints "Forwarding configuration conflict", exits, and
# the base image quietly falls back to slirp. The VM then still runs, with
# different forwarding and no socket a policy can attach to, and nothing says
# why unless you read passt's own log. That is a long way to travel for setting
# PASST_OPTS="-t all".
#
# So when PASST_OPTS carries a forwarding spec, the ports the image would have
# added for that protocol are handed to HOST_PORTS, which is the list it skips.
reconcilePasstPorts() {

  local opts="${PASST_OPTS:-}"
  [ -z "$opts" ] && return 0

  # Every other mode ignores PASST_OPTS, so there is nothing to reconcile.
  local mode="${NETWORK:-passt}"
  [[ "${mode,,}" != "passt" ]] && return 0

  local wantsTCP="" wantsUDP=""
  [[ " $opts " == *" -t "* || "$opts" == *"--tcp-ports"* ]] && wantsTCP=1
  [[ " $opts " == *" -u "* || "$opts" == *"--udp-ports"* ]] && wantsUDP=1
  [ -z "$wantsTCP" ] && [ -z "$wantsUDP" ] && return 0

  local defaults="22/tcp"
  [[ "${BOOT_MODE:-}" == windows* ]] && defaults="3389/tcp,3389/udp"

  # USER_PORTS is only given a default by /run/network.sh, which has not run
  # yet, so it may still be unset here.
  local user="${USER_PORTS:-}"

  local taken="" entry num proto
  for entry in ${defaults//,/ } ${user//,/ }; do
    entry="${entry// /}"
    [ -z "$entry" ] && continue

    proto="tcp"
    num="$entry"
    case "$entry" in
      */udp ) proto="udp"; num="${entry%/udp}" ;;
      */tcp ) proto="tcp"; num="${entry%/tcp}" ;;
    esac
    [ -z "$num" ] && continue

    if [[ "$proto" == "tcp" && -n "$wantsTCP" ]] || [[ "$proto" == "udp" && -n "$wantsUDP" ]]; then
      taken+="$num/$proto,"
    fi
  done

  warnPasstPortBudget "$opts"

  [ -z "$taken" ] && return 0
  taken="${taken%,}"

  HOST_PORTS="${HOST_PORTS:+${HOST_PORTS},}${taken}"

  vmLog "PASST_OPTS forwards ports itself, so $taken is left entirely to it."
  vmLog "The \"already in HOST_PORTS\" warning below is that, and is expected."

  return 0
}

reconcilePasstPorts

# Image-specific hooks (staging a baked disk image, preparing installer media,
# and so on). Sourced in name order so ordering is explicit in the filename.
if [ -d /run/hooks.d ]; then
  for _vm_hook in /run/hooks.d/*.sh; do
    [ -e "$_vm_hook" ] || continue
    # shellcheck disable=SC1090
    . "$_vm_hook"
  done
  unset _vm_hook
fi

return 0
