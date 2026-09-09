#!/usr/bin/env bash
# Image hook for the macOS VM, sourced from /run/start.sh before the base
# image's own scripts run.
#
# It stages the recovery image that was baked in at build time into /storage,
# so install.sh finds it already there and never contacts Apple. Handing it over
# this way rather than as /boot.dmg is deliberate: upstream validates a
# user-supplied /boot.dmg by looking for boot.efi inside it with 7z, which
# cannot read the APFS volume in every recovery image Apple has shipped since
# Big Sur, so that path rejects perfectly good images.
#
# It also prints the steps that still have to be taken in the installer GUI.
# Apple's installer has no unattended mode, so the last few steps are manual;
# saying so up front is better than leaving a booted recovery screen unexplained.

set -Eeuo pipefail

: "${STORAGE:=/storage}"
: "${VERSION:=15}"

_MACOS_BAKED="/opt/baked/base.dmg"

# _macosFirstRun reports whether this storage volume has no macOS installed yet.
# utils.sh is not loaded at this point, so the disk layouts upstream can produce
# are checked directly.
_macosFirstRun() {

  local disk
  for disk in "$STORAGE/data.img" "$STORAGE/data.qcow2" \
              "$STORAGE/${VERSION,,}/data.img" "$STORAGE/${VERSION,,}/data.qcow2"; do
    [ -s "$disk" ] && return 1
  done

  return 0
}

# _macosStageRecovery copies the baked image into the layout install.sh expects.
_macosStageRecovery() {

  local baked_version dest tmp

  [ -s "$_MACOS_BAKED" ] || return 0

  # Only usable for the version it was built for; upstream keeps one
  # installation per version under /storage/<version>.
  baked_version=$(tr -d '[:space:]' < /opt/baked/version 2>/dev/null || true)
  if [ "${baked_version,,}" != "${VERSION,,}" ]; then
    echo "❯ The baked recovery image is macOS ${baked_version:-unknown}, but VERSION is $VERSION."
    echo "❯ It will be downloaded from Apple instead."
    return 0
  fi

  # An existing image in either layout wins, so a user-supplied one is kept.
  [ -s "$STORAGE/base.dmg" ] && return 0
  dest="$STORAGE/${VERSION,,}/base.dmg"
  [ -s "$dest" ] && return 0

  if ! mkdir -p "$STORAGE/${VERSION,,}"; then
    echo "❯ Warning: cannot create $STORAGE/${VERSION,,}; the recovery image will be downloaded instead." >&2
    return 0
  fi

  echo "❯ Staging the baked macOS $VERSION recovery image into $dest..."

  # Publish under a temporary name first: a copy interrupted half way would
  # otherwise look like a complete image on the next start.
  tmp="$dest.tmp"
  rm -f "$tmp"

  if ! cp -f "$_MACOS_BAKED" "$tmp"; then
    rm -f "$tmp"
    echo "❯ Warning: could not stage the recovery image; it will be downloaded instead." >&2
    return 0
  fi

  sync

  if ! mv -f "$tmp" "$dest"; then
    rm -f "$tmp"
    echo "❯ Warning: could not stage the recovery image; it will be downloaded instead." >&2
    return 0
  fi

  echo "❯ Staged $(du -h "$dest" | awk '{print $1}') of recovery image."
  return 0
}

if _macosFirstRun; then

  if [ -s "$_MACOS_BAKED" ]; then
    _macosStageRecovery
  else
    echo "❯ No recovery image is baked into this container; it will be downloaded from Apple."
  fi

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

unset -f _macosFirstRun _macosStageRecovery
unset _MACOS_BAKED

return 0
