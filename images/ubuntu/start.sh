#!/usr/bin/env bash
# Custom startup hook for the pre-baked Ubuntu image.
# Sourced by /run/entry.sh BEFORE qemux/qemu's install.sh runs.
#
# Job: stage the baked qcow2 into the persistent storage volume on first run,
# so subsequent boots reuse the modified disk (packages installed, files written, etc.)
# instead of starting from the pristine cloud image every time.

set -Eeuo pipefail

: "${STORAGE:=/storage}"
BAKED="/opt/baked/boot.qcow2"
DEST="${STORAGE}/boot.qcow2"

# Make sure the storage volume exists and is writable.
mkdir -p "${STORAGE}"

if [ ! -f "${DEST}" ]; then
    if [ -f "${BAKED}" ]; then
        echo "[start.sh] First run detected, staging baked qcow2 into ${DEST}..."
        # cp -f is fine; qcow2 sparse-copies on most filesystems.
        cp -f "${BAKED}" "${DEST}"
        sync
        echo "[start.sh] Staged $(du -h "${DEST}" | awk '{print $1}') of qcow2 to ${DEST}."
    else
        echo "[start.sh] No baked qcow2 found at ${BAKED}, falling back to BOOT env."
    fi
else
    echo "[start.sh] Existing ${DEST} found, reusing it."
fi

# We populate /boot.qcow2 only if the user hasn't bound their own override.
# qemux/qemu's install.sh searches / first, then $STORAGE; placing the file
# in $STORAGE (above) is enough — we don't need to symlink it to /.

return 0
