#!/usr/bin/env python3
"""Tests for verify-recovery.py.

Apple's private key is not available, so the tests substitute a throwaway
keypair generated for this file alone and sign chunklists with it. That
exercises the real padding and verification path; only the modulus differs.

Run with: python3 images/macos/verify-recovery_test.py
"""

import hashlib
import importlib.util
import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

spec = importlib.util.spec_from_file_location(
    "verify_recovery", os.path.join(HERE, "verify-recovery.py"))
vr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vr)

# A 2048-bit RSA keypair that exists only to sign test chunklists. It has no
# relationship to Apple's key and guards nothing.
TEST_N = 0xd9e1f7105d047f3f7f348e82b8f62a477033ad71a3c030c373956ca5a927f7c7ac09d32cea215800413c5fe76fb8f1e5b10761a06f4d26446276054a2cdf6bd33376550bc1eab109320cd6f1182b323a97d82686882312a6331c930032d41a33e770a7c640fbe42b2467c62ea9c2419978b801bee3f881f885134bc19c40af6d99cfe64dc9f0fb2a4e8510db3779c729da64cf02380900c31d428aebb48d4a81bbe440b549d819249f3319752fad8be3509d2e93e1a5c58de541f8fb259d136fe18c16ea3be43cdf21e1eeb5137f20dbd7b0df110961de174183d60539bd0edd19259a9475cc308ad3d2dbe5804e37c3adf8b416d1b97c38ea3b6980266e108d
TEST_D = 0x4b841c8800dd4ea738d503f1bdde9fffbb9d45a7a5ec365a7fc491f006e571e53435018ac7294061723ad5389749e0194e96b2d912ca88115a98f23367c3161190fc19f4e5c48c9095d6ca66ac8c482ff3b1f8845749e4ac52f9bbdf6d3e83486b166a27f61cf7d3961e1b9bcfbda2d3e8f9c9ad1a4166f6b654de445ffe316ea4d624e8794b244faac19c3fbd516428ba42bf2348f389cefcac559e002d4258d91e1012ceed7b82c526fdb974983c3221e349ff2158661e43838c634911fc599ab4411cffcee5029e97fe4fd7af854d09cdfc7363118326f93c1565be4a694763c5fc510541a84dfd795f3676ad404b9216b6d32a568b1d6991c9fd9c6738c7

vr.APPLE_EFI_ROM_PUBLIC_KEY = TEST_N


def build(tmp, image, chunk_size=4096, signature_method=1, magic=b"CNKL",
          break_signature=False):
    """Write a chunklist and image pair, returning both paths."""
    chunks = [image[i:i + chunk_size] for i in range(0, len(image), chunk_size)]
    header = struct.pack("<4sIBBBxQQQ", magic, 0x24, 1, 1, signature_method,
                         len(chunks), 0x24, 0x24 + 0x24 * len(chunks))
    table = b"".join(struct.pack("<I32s", len(c), hashlib.sha256(c).digest())
                     for c in chunks)
    digest = hashlib.sha256(header + table).digest()

    if signature_method == 1:
        signed = pow(vr.pkcs1v15_sha256(digest), TEST_D, TEST_N)
        if break_signature:
            signed ^= 1
        trailer = signed.to_bytes(256, "little")
    else:
        trailer = digest

    cl = os.path.join(tmp, "cl.bin")
    img = os.path.join(tmp, "img.bin")
    with open(cl, "wb") as f:
        f.write(header + table + trailer)
    with open(img, "wb") as f:
        f.write(image)
    return cl, img


def expect_invalid(name, fn, fragment):
    try:
        fn()
    except vr.Invalid as e:
        if fragment in str(e):
            return True, name
        return False, f"{name}: rejected for the wrong reason: {e}"
    return False, f"{name}: accepted, but must be rejected"


def main():
    results = []

    with tempfile.TemporaryDirectory() as tmp:
        image = os.urandom(10000)

        cl, img = build(tmp, image)
        size = vr.verify_image(img, vr.read_chunklist(cl))
        results.append((size == len(image), "a correctly signed chunklist verifies"))

        cl, img = build(tmp, image)
        tampered = bytearray(image)
        tampered[5000] ^= 0xFF
        with open(img, "wb") as f:
            f.write(bytes(tampered))
        results.append(expect_invalid(
            "a tampered image is rejected",
            lambda: vr.verify_image(img, vr.read_chunklist(cl)),
            "does not match"))

        cl, _ = build(tmp, image, break_signature=True)
        results.append(expect_invalid(
            "a forged signature is rejected",
            lambda: vr.read_chunklist(cl), "not Apple's"))

        cl, _ = build(tmp, image, signature_method=2)
        results.append(expect_invalid(
            "an unsigned chunklist is rejected",
            lambda: vr.read_chunklist(cl), "not signed"))

        cl, _ = build(tmp, image, magic=b"XXXX")
        results.append(expect_invalid(
            "a file that is not a chunklist is rejected",
            lambda: vr.read_chunklist(cl), "not a chunklist"))

        cl, img = build(tmp, image)
        with open(img, "ab") as f:
            f.write(b"appended")
        results.append(expect_invalid(
            "an image longer than the chunklist is rejected",
            lambda: vr.verify_image(img, vr.read_chunklist(cl)),
            "longer than"))

        cl, img = build(tmp, image)
        with open(img, "rb") as f:
            short = f.read()[:-100]
        with open(img, "wb") as f:
            f.write(short)
        results.append(expect_invalid(
            "a truncated image is rejected",
            lambda: vr.verify_image(img, vr.read_chunklist(cl)),
            "ends inside"))

    failed = 0
    for ok, name in results:
        print(("PASS  " if ok else "FAIL  ") + name)
        failed += 0 if ok else 1

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
