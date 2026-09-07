#!/usr/bin/env python3
"""Verify a macOS recovery image against Apple's signed chunklist.

Apple's recovery service answers over TLS with a CDN link for the image and a
second one for a chunklist: a list of SHA-256 digests, one per chunk of the
image, signed with Apple's EFI ROM key. Checking that signature and then every
chunk is what makes the bulk download trustworthy no matter how it travelled,
which matters here because the CDN refuses TLS for those signed links and the
result is baked into a container image other people pull.

Nothing outside the standard library is used: the signature is RSA with
exponent 65537, so verifying it is one modular exponentiation.

Usage: verify-recovery.py <chunklist> <image>
"""

import hashlib
import struct
import sys

# Apple's EFI ROM public key, the modulus that signs recovery chunklists.
# Same value used by github.com/kholia/OSX-KVM and other recovery tooling; a
# signature that verifies against it could only have been produced by Apple.
APPLE_EFI_ROM_PUBLIC_KEY = 0xC3E748CAD9CD384329E10E25A91E43E1A762FF529ADE578C935BDDF9B13F2179D4855E6FC89E9E29CA12517D17DFA1EDCE0BEBF0EA7B461FFE61D94E2BDF72C196F89ACD3536B644064014DAE25A15DB6BB0852ECBD120916318D1CCDEA3C84C92ED743FC176D0BACA920D3FCF3158AFF731F88CE0623182A8ED67E650515F75745909F07D415F55FC15A35654D118C55A462D37A3ACDA08612F3F3F6571761EFCCBCC299AEE99B3A4FD6212CCFFF5EF37A2C334E871191F7E1C31960E010A54E86FA3F62E6D6905E1CD57732410A3EB0C6B4DEFDABE9F59BF1618758C751CD56CEF851D1C0EAA1C558E37AC108DA9089863D20E2E7E4BF475EC66FE6B3EFDCF

RSA_EXPONENT = 0x10001

CHUNKLIST_HEADER = struct.Struct("<4sIBBBxQQQ")  # 0x24 bytes
CHUNKLIST_CHUNK = struct.Struct("<I32s")  # 0x24 bytes

READ_SIZE = 1 << 20


class Invalid(Exception):
    """The chunklist or the image did not verify."""


def pkcs1v15_sha256(digest: bytes, modulus_bits: int = 2048) -> int:
    """Build the PKCS#1 v1.5 encoding a SHA-256 RSA signature decrypts to."""
    # DigestInfo for SHA-256, then 0x00 || 0x01 || 0xff padding || 0x00 in front.
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    tail = prefix + digest
    padding = b"\xff" * (modulus_bits // 8 - len(tail) - 3)
    return int.from_bytes(b"\x00\x01" + padding + b"\x00" + tail, "big")


def read_chunklist(path: str):
    """Return the chunks a signed chunklist lists, refusing anything unsigned."""
    with open(path, "rb") as f:
        running = hashlib.sha256()

        data = f.read(CHUNKLIST_HEADER.size)
        if len(data) != CHUNKLIST_HEADER.size:
            raise Invalid("chunklist is too short to hold a header")
        running.update(data)

        (magic, header_size, file_version, chunk_method,
         signature_method, chunk_count, chunk_offset,
         signature_offset) = CHUNKLIST_HEADER.unpack(data)

        if magic != b"CNKL":
            raise Invalid(f"not a chunklist: magic {magic!r}")
        if header_size != CHUNKLIST_HEADER.size:
            raise Invalid(f"unexpected header size {header_size}")
        if file_version != 1 or chunk_method != 1:
            raise Invalid(f"unsupported chunklist version {file_version}/{chunk_method}")
        if chunk_count <= 0:
            raise Invalid("chunklist lists no chunks")
        if chunk_offset != CHUNKLIST_HEADER.size:
            raise Invalid(f"unexpected chunk offset {chunk_offset}")
        if signature_offset != chunk_offset + CHUNKLIST_CHUNK.size * chunk_count:
            raise Invalid("signature does not follow the chunk table")

        chunks = []
        for _ in range(chunk_count):
            data = f.read(CHUNKLIST_CHUNK.size)
            if len(data) != CHUNKLIST_CHUNK.size:
                raise Invalid("chunk table is shorter than the header claims")
            running.update(data)
            chunks.append(CHUNKLIST_CHUNK.unpack(data))

        digest = running.digest()

        if signature_method != 1:
            # Method 2 carries a bare digest instead of a signature, which
            # proves nothing about who produced the file.
            raise Invalid(f"chunklist is not signed (signature method {signature_method})")

        signature = f.read(256)
        if len(signature) != 256:
            raise Invalid("signature is truncated")
        if f.read(1) != b"":
            raise Invalid("trailing data after the signature")

        recovered = pow(int.from_bytes(signature, "little"), RSA_EXPONENT,
                        APPLE_EFI_ROM_PUBLIC_KEY)
        if recovered != pkcs1v15_sha256(digest):
            raise Invalid("chunklist signature is not Apple's")

    return chunks


def verify_image(path: str, chunks) -> int:
    """Check the image against the chunk digests, returning its size."""
    total = 0
    with open(path, "rb") as f:
        for index, (size, expected) in enumerate(chunks, 1):
            remaining = size
            h = hashlib.sha256()
            while remaining:
                block = f.read(min(remaining, READ_SIZE))
                if not block:
                    raise Invalid(f"image ends inside chunk {index}")
                h.update(block)
                remaining -= len(block)
            if h.digest() != expected:
                raise Invalid(f"chunk {index} does not match the chunklist")
            total += size

        if f.read(1):
            raise Invalid("image is longer than the chunklist describes")

    return total


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 64

    chunklist, image = sys.argv[1], sys.argv[2]

    try:
        chunks = read_chunklist(chunklist)
        size = verify_image(image, chunks)
    except Invalid as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print(f"Recovery image verified against Apple's signed chunklist: "
          f"{len(chunks)} chunks, {size} bytes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
