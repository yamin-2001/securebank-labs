#!/usr/bin/env python3
"""Generate salted PBKDF2 password hashes for the Lab 7 fix exercise.

The output format must match core/PasswordHasher.pbkdf2() exactly:

    pbkdf2-sha256$<iterations>$<salt-b64>$<hash-b64>

The salt is the raw random bytes, base64-encoded (Java's
Base64.getEncoder()). The derived key is likewise base64-encoded.

Usage:
    python3 verify/payloads/hash_passwords.py

Prints one line per seeded user. Paste the output into
backend/src/main/resources/data.sql to replace the unsalted MD5 hashes.
"""

import base64
import hashlib
import os

USERS = [
    ("admin", "admin"),
    ("alice", "password123"),
    ("bob", "qwerty"),
    ("carol", "letmein"),
    ("dave", "changeme"),
]

ITERATIONS = 100_000


def hash_password(password: str, salt_b64: str | None = None) -> str:
    if salt_b64 is None:
        salt_b64 = base64.b64encode(os.urandom(16)).decode()
    # Java's PBEKeySpec takes the salt as a char array and
    # PBKDF2WithHmacSHA256 re-encodes those chars as UTF-8 bytes. So the
    # salt is the base64 TEXT, not the bytes it decodes to. Match that here.
    salt = salt_b64.encode()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS, dklen=32)
    return (
        f"pbkdf2-sha256${ITERATIONS}${salt_b64}$"
        f"{base64.b64encode(dk).decode()}"
    )


if __name__ == "__main__":
    for user, password in USERS:
        print(f"{user}\t{hash_password(password)}")
