"""LAB 5 (A02 — Security Misconfiguration): default admin credentials.

Exploit: POST /admin-panel/login with username=admin, password=admin. On the
vulnerable build the panel accepts the shipped default and hands back an
admin session. After the fix the default password no longer authenticates.
"""

from common import Client, Result, Verdict

ID = 5
TITLE = "Default admin credentials — admin/admin opens the operations console"
ENDPOINT = "POST /admin-panel/login"
AFFECTED = "backend/src/main/java/com/securebank/labs/a02/AdminPanelController.java -> login(Map)"

DEFAULT_USER = "admin"
DEFAULT_PASS = "admin"


def run(ctx: Client) -> Result:
    r = ctx.post(
        "/admin-panel/login",
        json={"username": DEFAULT_USER, "password": DEFAULT_PASS},
    )

    if r.status_code == 200:
        try:
            body = r.json()
        except ValueError:
            return Result(
                Verdict.VULNERABLE,
                f"HTTP 200 from the admin panel with admin/admin: {r.text[:200]}",
            )
        if body.get("authenticated") is True:
            return Result(
                Verdict.VULNERABLE,
                "admin/admin was accepted and an admin session was returned",
            )
        return Result(Verdict.VULNERABLE, f"admin/admin returned HTTP 200: {r.text[:200]}")

    if r.status_code in (401, 403):
        return Result(
            Verdict.FIXED,
            f"the default credentials were refused (HTTP {r.status_code})",
        )

    return Result(Verdict.INCONCLUSIVE, f"unexpected HTTP {r.status_code}: {r.text[:200]}")
