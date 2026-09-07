#!/usr/bin/env bash
# Image hook for the pre-baked Ubuntu image, sourced from /run/start.sh before
# the base image's own install/disk scripts.
#
# It copies the baked cloud image into persistent storage on the first run and
# grows that boot image when DISK_SIZE/BOOT_DISK_SIZE is increased at container
# start.

set -Eeuo pipefail

: "${STORAGE:=/storage}"
: "${DISK_SIZE:=64G}"

BAKED="/opt/baked/boot.qcow2"
DEST="${STORAGE}/boot.qcow2"

normalize_size() {
    local size="${1// /}"

    [ -z "${size}" ] && return 1

    case "${size,,}" in
        max|half)
            # qemux/qemu supports these for data disks. For the baked boot disk
            # we require an explicit size so the result is deterministic.
            return 2
            ;;
    esac

    if [[ "${size}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        size="${size}G"
    fi

    size="$(echo "${size^^}" | sed 's/MB/M/g;s/GB/G/g;s/TB/T/g')"
    numfmt --from=iec "${size}" >/dev/null 2>&1 || return 1
    echo "${size}"
}

qcow2_virtual_bytes() {
    local image="$1"
    qemu-img info -f qcow2 "${image}" \
        | sed -n 's/^virtual size:.*(\([0-9][0-9]*\) bytes).*/\1/p' \
        | head -n 1
}

resize_boot_disk() {
    local requested="${BOOT_DISK_SIZE:-${DISK_SIZE:-}}"
    local normalized desired current

    if normalized="$(normalize_size "${requested}")"; then
        :
    else
        local rc=$?
        case "${rc}" in
            2)
                echo "[start.sh] BOOT_DISK_SIZE/DISK_SIZE=${requested}: max/half are not supported for boot.qcow2; keeping current size."
                ;;
            *)
                echo "[start.sh] BOOT_DISK_SIZE/DISK_SIZE=${requested}: invalid size; keeping current size."
                ;;
        esac
        return 0
    fi

    desired="$(numfmt --from=iec "${normalized}")"
    current="$(qcow2_virtual_bytes "${DEST}")"

    if [ -z "${current}" ]; then
        echo "[start.sh] Could not read current virtual size of ${DEST}; skipping resize."
        return 0
    fi

    if (( desired > current )); then
        echo "[start.sh] Growing ${DEST} from $(numfmt --to=iec --suffix=B "${current}") to ${normalized}..."
        qemu-img resize -f qcow2 "${DEST}" "${normalized}"
    elif (( desired < current )); then
        echo "[start.sh] Requested boot disk ${normalized} is smaller than current $(numfmt --to=iec --suffix=B "${current}"); shrinking is not supported."
    else
        echo "[start.sh] Boot disk already has requested virtual size ${normalized}."
    fi
}

mkdir -p "${STORAGE}"

if [ ! -s "${DEST}" ]; then
    if [ -s "${BAKED}" ]; then
        echo "[start.sh] First run detected, staging baked qcow2 into ${DEST}..."
        # Publish under a temporary name first: a copy interrupted half way
        # would otherwise look like a complete disk on the next start.
        rm -f "${DEST}.tmp"
        cp -f "${BAKED}" "${DEST}.tmp"
        sync
        mv -f "${DEST}.tmp" "${DEST}"
        echo "[start.sh] Staged $(du -h "${DEST}" | awk '{print $1}') of qcow2 to ${DEST}."
    else
        echo "[start.sh] No baked qcow2 found at ${BAKED}, falling back to BOOT env."
    fi
else
    echo "[start.sh] Existing ${DEST} found, reusing it."
fi

if [ -f "${DEST}" ]; then
    resize_boot_disk
fi

return 0
