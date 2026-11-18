"""LAB 2 (A01 — Broken Access Control): missing role check on /api/admin/**.

Exploit: authenticate as a normal customer (alice) and call
GET /api/admin/users. On the vulnerable build the matcher only requires
`.authenticated()`, so alice gets 200 and every user in the system including
password hashes. After the fix (`.hasRole("ADMIN")`) the call is 403.
"""

from common import Client, Result, Verdict

ID = 2
TITLE = "Privilege escalation — customer reaches the admin API"
ENDPOINT = "GET /api/admin/users, GET /api/admin/accounts"
AFFECTED = "backend/src/main/java/com/securebank/security/SecurityConfig.java -> apiChain() matcher for /api/admin/**"


def run(ctx: Client) -> Result:
    alice = ctx.token("alice")

    r = ctx.get("/api/admin/users", token=alice)

    if r.status_code == 200:
        try:
            users = r.json()
        except ValueError:
            return Result(Verdict.INCONCLUSIVE, f"HTTP 200 but body is not JSON: {r.text[:200]}")
        if isinstance(users, list) and len(users) > 1:
            with_hash = any("password_hash" in u for u in users if isinstance(u, dict))
            return Result(
                Verdict.VULNERABLE,
                f"alice (customer) listed {len(users)} users"
                + (" including password hashes" if with_hash else ""),
            )
        return Result(Verdict.VULNERABLE, "alice (customer) reached /api/admin/users (HTTP 200)")

    if r.status_code == 403:
        return Result(Verdict.FIXED, "role check enforced — HTTP 403 for a customer")

    if r.status_code == 401:
        return Result(
            Verdict.INCONCLUSIVE,
            "alice's token was rejected as unauthenticated — the auth path is broken, "
            "not the role check",
        )

    return Result(Verdict.INCONCLUSIVE, f"unexpected HTTP {r.status_code}: {r.text[:200]}")
