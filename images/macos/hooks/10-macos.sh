#!/usr/bin/env bash
# Image hook for the macOS VM, sourced from /run/start.sh.
#
# It reports which recovery image the container is about to use and, on a fresh
# volume, prints the steps that still have to be taken in the installer GUI.
# Apple's installer has no unattended mode, so the last few steps are manual;
# saying so up front is better than leaving a booted recovery screen unexplained.

set -Eeuo pipefail

: "${STORAGE:=/storage}"
: "${VERSION:=15}"

_macosFirstRun() {

  # A data disk in either the versioned or the legacy layout means macOS has
  # already been installed here.
  local disk
  for disk in "$STORAGE/data.img" "$STORAGE/data.qcow2" \
              "$STORAGE/${VERSION,,}/data.img" "$STORAGE/${VERSION,,}/data.qcow2"; do
    [ -s "$disk" ] && return 1
  done

  return 0
}

if [ -s /boot.dmg ]; then
  echo "❯ Using the recovery image baked into this container."
else
  echo "❯ No recovery image is baked in; it will be downloaded from Apple now."
fi

if _macosFirstRun; then
  echo "❯ ---------------------------------------------------------------"
  echo "❯  First start: the VM boots into macOS Recovery."
  echo "❯  Open the web console on port 8006 and:"
  echo "❯    1. pick a language"
  echo "❯    2. Disk Utility -> select the largest QEMU disk -> Erase"
  echo "❯         name: Macintosh HD    format: APFS    scheme: GUID"
  echo "❯    3. quit Disk Utility, choose 'Reinstall macOS', follow the wizard"
  echo "❯  Apple ships no unattended installer, so these steps are manual."
  echo "❯  Everything after that persists in the mounted /storage volume."
  echo "❯ ---------------------------------------------------------------"
fi

unset -f _macosFirstRun

return 0
