"""LAB 1 (A01 — Broken Access Control): IDOR on GET /api/accounts/{id}.

Exploit: authenticate as alice, then fetch an account number that belongs to
bob. On the vulnerable build the response is 200 and carries bob's data. After
the fix (an ownership check in AccountService.getAccount) the same request is
refused with 403.
"""

from common import Client, Result, Verdict

ID = 1
TITLE = "IDOR — read another customer's account by changing the id"
ENDPOINT = "GET /api/accounts/{id}"
AFFECTED = "labs/a01/AccountService.java -> getAccount(Long, Long)"


def run(ctx: Client) -> Result:
    alice = ctx.token("alice")
    bob = ctx.token("bob")

    # Bob's own account is the one we try to steal.
    own = ctx.get("/api/accounts", token=bob).json()
    bob_accounts = [a for a in own if a.get("owner_id") != 1]
    if not bob_accounts:
        return Result(Verdict.INCONCLUSIVE, "could not locate a second account to steal")
    target_id = bob_accounts[0]["id"]

    r = ctx.get(f"/api/accounts/{target_id}", token=alice)

    if r.status_code == 200:
        body = r.json()
        owner = body.get("owner_id")
        if owner is not None and owner != 1:
            return Result(
                Verdict.VULNERABLE,
                f"alice (user_id 1) read account {target_id} owned by user_id {owner}",
            )
        return Result(
            Verdict.VULNERABLE,
            f"alice (user_id 1) read account {target_id} with no ownership check (HTTP 200)",
        )

    if r.status_code in (401, 403, 404):
        return Result(
            Verdict.FIXED,
            f"ownership enforced — HTTP {r.status_code} for account {target_id}",
        )

    return Result(Verdict.INCONCLUSIVE, f"unexpected HTTP {r.status_code}: {r.text[:200]}")
