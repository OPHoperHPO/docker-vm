#!/usr/bin/env bash
#
# Downloads a macOS recovery image from Apple at *build* time.
#
# dockur/macos fetches this on the container's first start, which means the
# first boot of a fresh VM depends on Apple's servers being reachable and adds
# several minutes before anything appears on screen. Baking the image in matches
# what the Ubuntu and Windows images in this repository do: the container starts
# straight into the macOS installer with no network I/O for the OS itself.
#
# The image is validated here rather than at run time, so a truncated or
# non-bootable download fails the build instead of a user's first boot.
#
# Usage: fetch-recovery.sh <version> <output.dmg>
#   version   macOS name or major version (sequoia, 15, sonoma, 14, ...)

set -Eeuo pipefail

VERSION="${1:?usage: fetch-recovery.sh <version> <output.dmg>}"
OUTPUT="${2:?usage: fetch-recovery.sh <version> <output.dmg>}"

# Apple selects the recovery catalog by board identifier, so each macOS
# generation maps to a model that shipped with it. Kept in step with
# https://github.com/dockur/macos/blob/master/src/install.sh
boardFor() {
  case "${1,,}" in
    "tahoe" | "26"* | "16"* ) echo "Mac-CFF7D910A743CAAF" ;;
    "sequoia" | "15"* )       echo "Mac-937A206F2EE63C01" ;;
    "sonoma" | "14"* )        echo "Mac-827FAC58A8FDFA22" ;;
    "ventura" | "13"* )       echo "Mac-4B682C642B45593E" ;;
    "monterey" | "12"* )      echo "Mac-B809C3757DA9BB8D" ;;
    "bigsur" | "big-sur" | "11"* ) echo "Mac-2BD1B31983FE1663" ;;
    "catalina" | "10"* )      echo "Mac-00BE6ED71E35EB86" ;;
    * ) return 1 ;;
  esac
}

randomHex() {
  # Apple's request nonces are opaque session tokens, not machine identity.
  head -c "$(( $1 / 2 ))" /dev/urandom | od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F'
}

BOARD=$(boardFor "$VERSION") || {
  echo "ERROR: unknown macOS version \"$VERSION\"." >&2
  exit 64
}

echo "Requesting the ${VERSION} recovery image (board $BOARD) from Apple..."

SESSION=$(curl --disable --max-time 60 -sS -v \
    -H "Host: osrecovery.apple.com" \
    -H "Connection: close" \
    -A "InternetRecovery/1.0" \
    https://osrecovery.apple.com/ 2>&1 \
  | tr ';' '\n' | awk -F'session=|;' '/session=/ {print $2; exit}')

if [ -z "$SESSION" ]; then
  echo "ERROR: Apple did not return a recovery session cookie." >&2
  exit 65
fi

RESPONSE=$(mktemp)
trap 'rm -f "$RESPONSE"' EXIT

curl --disable --max-time 120 -sS --show-error --fail-with-body \
  --request POST \
  --header "Host: osrecovery.apple.com" \
  --header "Connection: close" \
  --user-agent "InternetRecovery/1.0" \
  --cookie "session=\"${SESSION}\"" \
  --header "Content-Type: text/plain" \
  --data "cid=$(randomHex 16)
sn=00000000000000000
bid=${BOARD}
k=$(randomHex 64)
fg=$(randomHex 64)
os=latest" \
  --output "$RESPONSE" \
  https://osrecovery.apple.com/InstallationPayload/RecoveryImage

INFO=$(tr ' ' '\n' < "$RESPONSE")
URL=$(echo "$INFO" | grep 'oscdn' | grep 'dmg' | grep -v 'chunklist' | head -n 1 || :)
TOKEN=$(echo "$INFO" | grep 'expires' | grep 'dmg' | grep -v 'chunklist' | head -n 1 || :)

# Apple also returns a chunklist: SHA-256 digests for every chunk of the image,
# signed with its EFI ROM key. Both links arrive over TLS, so verifying the
# signature and then the chunks is what makes the image trustworthy however it
# was transferred.
CHUNK_URL=$(echo "$INFO" | grep 'oscdn' | grep 'chunklist' | head -n 1 || :)
CHUNK_TOKEN=$(echo "$INFO" | grep 'expires' | grep 'chunklist' | head -n 1 || :)

if [ -z "$URL" ] || [ -z "$TOKEN" ]; then
  echo "ERROR: unexpected response from Apple:" >&2
  head -c 2000 "$RESPONSE" >&2
  exit 66
fi

# Apple hands back plain-http CDN links and refuses TLS on them, while what they
# serve ends up baked into a container image other people pull. Size, qemu-img
# and a UDIF trailer are all things an attacker-supplied image passes, so the
# transport cannot be what this rests on: the chunklist signature is.
#
# TLS is still preferred where the CDN allows it, because it keeps the
# AssetToken off the wire.
download() {

  local url="$1"
  local dest="$2"
  local token="$3"

  echo "Downloading $url"

  # The CDN accepts range requests, so several connections cut a ~850 MB
  # download from tens of minutes to a couple on a CI runner.
  aria2c \
    --max-connection-per-server=8 \
    --split=8 \
    --min-split-size=1M \
    --max-tries=5 \
    --retry-wait=10 \
    --connect-timeout=30 \
    --timeout=60 \
    --auto-file-renaming=false \
    --allow-overwrite=true \
    --check-certificate=true \
    --console-log-level=warn \
    --summary-interval=30 \
    --header "Host: oscdn.apple.com" \
    --header "Connection: close" \
    --header "Cookie: AssetToken=${token}" \
    --user-agent "InternetRecovery/1.0" \
    --dir="$(dirname "$dest")" \
    --out="$(basename "$dest")" \
    "$url"
}

# fetch tries TLS first and falls back to the scheme Apple gave us, which is
# safe for anything the chunklist signature covers.
fetch() {

  local url="$1" dest="$2" token="$3" allow_plain="$4"
  local secure="$url"

  case "$url" in
    http://*) secure="https://${url#http://}" ;;
  esac

  if [ "$secure" != "$url" ] && download "$secure" "$dest" "$token"; then
    return 0
  fi

  rm -f -- "$dest" "$dest.aria2"

  if [ "$allow_plain" != "Y" ]; then
    echo "ERROR: could not download over TLS, and there is no signature to fall back on." >&2
    return 1
  fi

  echo "Apple's CDN refused TLS; retrying over http (the chunklist signature covers this)."
  download "$url" "$dest" "$token"
}

CHUNKLIST=""

if [ -n "$CHUNK_URL" ] && [ -n "$CHUNK_TOKEN" ]; then

  CHUNKLIST="${OUTPUT}.chunklist"
  rm -f -- "$CHUNKLIST" "$CHUNKLIST.aria2"

  if ! fetch "$CHUNK_URL" "$CHUNKLIST" "$CHUNK_TOKEN" "Y"; then
    echo "ERROR: could not download the chunklist." >&2
    exit 70
  fi

else

  echo "WARNING: Apple did not return a chunklist for this image." >&2
  echo "         Without it the download can only be trusted as far as TLS," >&2
  echo "         so plain http will not be accepted." >&2

fi

ALLOW_PLAIN="N"
[ -n "$CHUNKLIST" ] && ALLOW_PLAIN="Y"

if ! fetch "$URL" "$OUTPUT" "$TOKEN" "$ALLOW_PLAIN"; then
  rm -f -- "$OUTPUT" "$OUTPUT.aria2" "$CHUNKLIST"
  echo "ERROR: could not download the recovery image." >&2
  exit 71
fi

SIZE=$(stat -c%s "$OUTPUT")
echo "Downloaded $(numfmt --to=iec --suffix=B "$SIZE")."

if (( SIZE < 100000000 )); then
  echo "ERROR: the recovery image is only $SIZE bytes — the download is broken." >&2
  exit 67
fi

if ! qemu-img info "$OUTPUT" > /dev/null; then
  echo "ERROR: the downloaded file is not a valid disk image." >&2
  exit 68
fi

# A UDIF disk image ends with a 512-byte "koly" trailer. Checking it catches a
# truncated transfer or an error page that happened to be large enough to pass
# the size check.
#
# The contents are deliberately not inspected: since Big Sur the recovery
# volume inside is APFS, which 7z cannot read, so looking for boot.efi rejects
# every image Apple currently serves.
if [ "$(tail -c 512 "$OUTPUT" | head -c 4)" != "koly" ]; then
  echo "ERROR: the download does not end with a UDIF trailer; it is truncated or not a DMG." >&2
  exit 69
fi

if [ -n "$CHUNKLIST" ]; then
  if ! verify-recovery.py "$CHUNKLIST" "$OUTPUT"; then
    rm -f -- "$OUTPUT" "$CHUNKLIST"
    echo "ERROR: the recovery image does not match Apple's signed chunklist." >&2
    exit 72
  fi
  rm -f -- "$CHUNKLIST"
fi

echo "Recovery image ready: $(numfmt --to=iec --suffix=B "$SIZE"), UDIF trailer present."
