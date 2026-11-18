"""LAB 14 (A06 — Insecure Design): negative transfer amounts.

Exploit: send a transfer with a negative amount. On the vulnerable build the
amount is applied to both sides unchanged, so the sender's balance *grows*.
On the fixed build the request is rejected with a validation error.

The probe restores the balance it changes, so it does not leave the database
in a state that would confuse another lab's check.
"""

from common import Client, Result, Verdict

ID = 14
TITLE = "Negative transfer — create money from nothing"
ENDPOINT = "POST /api/transfers/send"
AFFECTED = "backend/src/main/java/com/securebank/labs/a06/TransferService.java -> send(...)"

FROM_ACCOUNT = 1  # ACC-1001, alice's
TO_ACCOUNT = 2  # ACC-1002, bob's
DELTA = 1000


def run(ctx: Client) -> Result:
    token = ctx.token("alice")

    before = _balance(ctx, token, FROM_ACCOUNT)
    if before is None:
        return Result(
            Verdict.INCONCLUSIVE,
            f"could not read alice's account — HTTP {before}: "
            "the balance was not readable",
        )

    r = ctx.post(
        "/api/transfers/send",
        token=token,
        json={
            "from_account_id": FROM_ACCOUNT,
            "to_account_id": TO_ACCOUNT,
            "amount": -DELTA,
            "note": "lab 14 probe",
        },
    )

    if r.status_code == 400 or r.status_code == 422:
        return Result(
            Verdict.FIXED,
            f"the negative transfer was rejected with HTTP {r.status_code}",
        )

    if r.status_code != 200:
        return Result(
            Verdict.INCONCLUSIVE,
            f"the transfer endpoint returned HTTP {r.status_code}: {r.text[:200]}",
        )

    after = _balance(ctx, token, FROM_ACCOUNT)

    # Put the money back, so the next lab sees the seeded balances.
    ctx.post(
        "/api/transfers/send",
        token=token,
        json={
            "from_account_id": FROM_ACCOUNT,
            "to_account_id": TO_ACCOUNT,
            "amount": DELTA,
            "note": "lab 14 probe (restore)",
        },
    )

    if before is None or after is None:
        return Result(Verdict.INCONCLUSIVE, "the account balance was not readable")

    if after > before:
        return Result(
            Verdict.VULNERABLE,
            f"a negative transfer increased alice's balance from {before} to {after}",
        )
    if after < before:
        return Result(
            Verdict.VULNERABLE,
            f"a negative transfer moved money the wrong way ({before} -> {after}) — "
            "the amount was applied without validation",
        )

    return Result(
        Verdict.FIXED,
        f"the balance was unchanged ({before}) — the negative amount was rejected",
    )


def _balance(ctx: Client, token: str, account_id: int) -> float | None:
    r = ctx.get(f"/api/accounts/{account_id}", token=token)
    if r.status_code != 200:
        return None
    try:
        body = r.json()
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    try:
        return float(body.get("balance"))
    except (TypeError, ValueError):
        return None
