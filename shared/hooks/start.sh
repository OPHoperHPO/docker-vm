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
