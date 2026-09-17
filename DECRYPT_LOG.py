#!/usr/bin/env python3
"""
ShadowSniff / MicrosoftEdgeUpdate log container decryptor.

Usage:
    pip install pycryptodome
    python DECRYPT_LOG.py <encrypted_log> <output.zip>
    (prompts for the password from the Telegram caption)
"""

import getpass
import hashlib
import sys

from Crypto.Cipher import AES

MAGIC = b"SNAES1"


def main() -> None:
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)

    src, dst = sys.argv[1], sys.argv[2]
    data = open(src, "rb").read()

    if data[:6] != MAGIC:
        print("[!] Not a SNAES1 container (already decrypted?).")
        open(dst, "wb").write(data)
        return

    version = int.from_bytes(data[6:8], "big")
    salt = data[8:24]
    nonce = data[24:36]
    ciphertext = data[36:-16]
    tag = data[-16:]

    if version != 1:
        print(f"[!] Unknown container version {version}.")
        sys.exit(1)

    password = getpass.getpass("Password (from the log caption): ").encode()

    key = hashlib.pbkdf2_hmac("sha256", password, salt, 10_000, 32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        plain = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        print("[!] Wrong password or corrupted container.")
        sys.exit(1)

    open(dst, "wb").write(plain)
    print(f"[+] Decrypted -> {dst}")


if __name__ == "__main__":
    main()
