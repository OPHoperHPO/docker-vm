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
URL=$(echo "$INFO" | grep 'oscdn' | grep 'dmg' | head -n 1 || :)
TOKEN=$(echo "$INFO" | grep 'expires' | grep 'dmg' | head -n 1 || :)

if [ -z "$URL" ] || [ -z "$TOKEN" ]; then
  echo "ERROR: unexpected response from Apple:" >&2
  head -c 2000 "$RESPONSE" >&2
  exit 66
fi

# Apple hands back a plain-http CDN URL. The image ends up baked into a
# published container image and carries no signature we can check, so anyone on
# the path could swap it — and the AssetToken would travel in the clear too.
# The same CDN serves https, so upgrade the scheme and only fall back if Apple's
# CDN genuinely refuses TLS.
download() {

  local url="$1"

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
    --header "Cookie: AssetToken=${TOKEN}" \
    --user-agent "InternetRecovery/1.0" \
    --dir="$(dirname "$OUTPUT")" \
    --out="$(basename "$OUTPUT")" \
    "$url"
}

SECURE_URL="$URL"
case "$URL" in
  http://*) SECURE_URL="https://${URL#http://}" ;;
esac

if [ "$SECURE_URL" != "$URL" ]; then
  if ! download "$SECURE_URL"; then
    echo "WARNING: the CDN refused TLS; retrying over plain http." >&2
    echo "WARNING: the recovery image is then unauthenticated in transit." >&2
    rm -f -- "$OUTPUT" "$OUTPUT.aria2"
    download "$URL"
  fi
else
  download "$URL"
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

echo "Recovery image verified: $(numfmt --to=iec --suffix=B "$SIZE"), UDIF trailer present."
