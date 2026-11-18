"""LAB 7 (A04 — Cryptographic Failures): unsalted MD5 password hashes.

Exploit: GET /api/crypto/hashes returns every user's password hash. On the
vulnerable build the hashes are unsalted MD5, so they can be cracked offline
in seconds. After the fix the endpoint reports a modern algorithm with a
per-user salt (or the hashes are no longer exposed at all).
"""

import hashlib

from common import Client, Result, Verdict

ID = 7
TITLE = "Unsalted MD5 password hashes — crack them offline in seconds"
ENDPOINT = "GET /api/crypto/hashes"
AFFECTED = "backend/src/main/java/com/securebank/core/Md5Hasher.java + backend/src/main/resources/data.sql"

# The seeded passwords, so the harness can prove a hash is crackable.
KNOWN = {
    "password123": "482c811da5d5b4bc6d497ffa98491e38",
    "qwerty": "d8578edf8458ce06fbc5bb76a58c5ca4",
    "admin": "21232f297a57a5a743894a0e4a801fc3",
}


def run(ctx: Client) -> Result:
    r = ctx.get("/api/crypto/hashes", token=ctx.token("alice"))
    if r.status_code != 200:
        return Result(
            Verdict.INCONCLUSIVE,
            f"the hashes endpoint returned HTTP {r.status_code}: {r.text[:200]}",
        )
    try:
        rows = r.json()
    except ValueError:
        return Result(Verdict.INCONCLUSIVE, f"body is not JSON: {r.text[:200]}")
    if not isinstance(rows, list) or not rows:
        return Result(Verdict.INCONCLUSIVE, "no hash rows returned")

    cracked = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        digest = (row.get("password_hash") or "").strip().lower()
        if not digest:
            continue
        # Crack it: try every known password against this digest.
        for plaintext, expected in KNOWN.items():
            if digest == expected:
                cracked.append(f"{row.get('username')}={plaintext}")
                break
            if digest == hashlib.md5(plaintext.encode()).hexdigest():
                cracked.append(f"{row.get('username')}={plaintext}")
                break

    if cracked:
        return Result(
            Verdict.VULNERABLE,
            "cracked unsalted MD5 hashes: " + ", ".join(cracked),
        )

    # No crack succeeded. That is only a fix if the scheme also changed.
    algorithms = {str(r.get("algorithm", "")).upper() for r in rows if isinstance(r, dict)}
    safe = {"BCRYPT", "ARGON2", "ARGON2ID", "SCRYPT", "PBKDF2",
            "PBKDF2-HMAC-SHA256", "PBKDF2-HMAC-SHA512"}
    if algorithms and algorithms <= safe:
        return Result(
            Verdict.FIXED,
            f"passwords now use {', '.join(sorted(algorithms))} — the MD5 hashes are gone",
        )

    return Result(
        Verdict.INCONCLUSIVE,
        f"no hash cracked, but the algorithm is still {sorted(algorithms) or 'unknown'}",
    )
