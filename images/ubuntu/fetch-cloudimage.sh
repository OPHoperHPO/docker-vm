#!/usr/bin/env bash
#
# Downloads an Ubuntu cloud image and checks it against Canonical's signed
# SHA256SUMS before it is baked into the container image.
#
# The image itself arrives over HTTPS with nothing tying the bytes to Canonical
# beyond the transport, and it ends up inside an image other people pull. The
# checksum file next to it is signed by Canonical's cloud-image key, so
# verifying that signature and then the digest anchors the download in something
# independent of how it travelled.
#
# Usage: fetch-cloudimage.sh <image-url> <output>
#
# Set UBUNTU_IMG_SHA256 to check against a known digest instead — for a mirror
# or a custom image that has no SHA256SUMS beside it.

set -Eeuo pipefail

URL="${1:?usage: fetch-cloudimage.sh <image-url> <output>}"
OUTPUT="${2:?usage: fetch-cloudimage.sh <image-url> <output>}"

KEY="${CANONICAL_KEY:-/usr/local/share/canonical-cloudimage-key.asc}"

# Canonical's "UEC Image Automatic Signing Key". This fingerprint is the trust
# root for every Ubuntu image this repository bakes: it is what says the bundled
# key really is Canonical's. Check it against
# https://cloud-images.ubuntu.com before changing it.
FINGERPRINT="D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# The cloud image is several hundred megabytes, and a transfer that dies in the
# middle of it is common enough to plan for: retry, and pick up where the last
# attempt stopped instead of starting the whole thing again. Resuming is safe
# because the result is checked against a digest either way — a resume onto the
# wrong bytes fails that check like any other bad download.
download() {
  local out=$1 url=$2
  local opts=(-fL --proto '=https' --retry 5 --retry-delay 5 --retry-all-errors)

  if curl "${opts[@]}" --continue-at - -o "$out" "$url"; then
    return 0
  fi

  # A server that does not do range requests refuses the resume; start over.
  rm -f "$out"
  curl "${opts[@]}" -o "$out" "$url"
}

echo "Downloading $URL"
download "$OUTPUT" "$URL"

SIZE=$(stat -c%s "$OUTPUT")
if (( SIZE < 100000000 )); then
  echo "ERROR: the cloud image is only $SIZE bytes — the download is broken." >&2
  exit 65
fi

ACTUAL=$(sha256sum "$OUTPUT" | cut -d' ' -f1)

if [ -n "${UBUNTU_IMG_SHA256:-}" ]; then

  EXPECTED="$UBUNTU_IMG_SHA256"
  SOURCE="UBUNTU_IMG_SHA256"

else

  NAME="${URL##*/}"
  BASE="${URL%/*}"

  echo "Fetching Canonical's SHA256SUMS for $NAME"
  download "$WORK/SHA256SUMS" "$BASE/SHA256SUMS"
  download "$WORK/SHA256SUMS.gpg" "$BASE/SHA256SUMS.gpg"

  # The bundled key is only worth anything if it is the one named above.
  FOUND=$(gpg --show-keys --with-colons "$KEY" 2>/dev/null | awk -F: '/^fpr:/ {print $10; exit}')
  if [ "$FOUND" != "$FINGERPRINT" ]; then
    echo "ERROR: bundled key has fingerprint ${FOUND:-none}, expected $FINGERPRINT." >&2
    exit 66
  fi

  gpg --dearmor < "$KEY" > "$WORK/keyring.gpg"

  if ! gpgv --keyring "$WORK/keyring.gpg" "$WORK/SHA256SUMS.gpg" "$WORK/SHA256SUMS"; then
    echo "ERROR: SHA256SUMS is not signed by Canonical's cloud-image key." >&2
    exit 67
  fi

  # SHA256SUMS lists names with a leading '*' for binary mode.
  EXPECTED=$(awk -v f="$NAME" '$2 == "*" f || $2 == f { print $1; exit }' "$WORK/SHA256SUMS")
  SOURCE="Canonical's signed SHA256SUMS"

  if [ -z "$EXPECTED" ]; then
    echo "ERROR: $NAME is not listed in SHA256SUMS." >&2
    echo "       For an image Canonical does not publish, pass UBUNTU_IMG_SHA256." >&2
    exit 68
  fi

fi

if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "ERROR: the cloud image does not match $SOURCE." >&2
  echo "       expected: $EXPECTED" >&2
  echo "       actual:   $ACTUAL" >&2
  rm -f "$OUTPUT"
  exit 69
fi

echo "Cloud image verified against $SOURCE: $ACTUAL"
