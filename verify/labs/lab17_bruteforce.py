"""LAB 17 (A07 — Identification and Authentication Failures): no rate limiting.

Exploit: hammer the login endpoint with wrong passwords for one account. On
the vulnerable build every attempt is served and nothing locks the account,
so a password sweep runs unimpeded. On the fixed build the account is
locked out (or the request is throttled) and the sweep cannot proceed.

The check watches for the *lockout*, not for a successful guess. That keeps
it independent of Lab 10, where the SQL injection in the same endpoint lets
any password through: a 200 there would be the injection, not the absence of
rate limiting.

The sweep targets a username that does not exist. The rate limiter counts
per username and refuses before it looks the user up, so a nonexistent name
is counted exactly like a real one — and using a name nobody else touches
means this check can never lock out an account another lab depends on.
"""

from common import Client, Result, Verdict

ID = 17
TITLE = "Brute force — the login endpoint never locks the account out"
ENDPOINT = "POST /api/auth/login"
AFFECTED = "backend/src/main/java/com/securebank/labs/a07/LoginAttemptService.java + labs/a07/AuthController.java -> login(...)"

# Weak passwords, tried in order.
CANDIDATES = [
    "password",
    "password1",
    "letmein",
    "welcome",
    "changeme",
    "qwerty",
    "qwerty123",
    "alice",
    "alice123",
    "Password123",
    "password123",
]

# A username that does not exist. Nothing else logs in as this name, so
# locking it out cannot affect any other lab.
PROBE_ACCOUNT = "brute-force-probe"


def run(ctx: Client) -> Result:
    # Sweep wrong passwords at the probe account.
    wrong_statuses = []
    for guess in CANDIDATES:
        r = ctx.post(
            "/api/auth/login", json={"username": PROBE_ACCOUNT, "password": guess}
        )
        wrong_statuses.append(r.status_code)

        # Locked out / throttled — the fix is in place.
        if r.status_code in (429, 423):
            return Result(
                Verdict.FIXED,
                f"the account was locked out after {len(wrong_statuses)} failed "
                f"attempts (HTTP {r.status_code})",
            )

    # The sweep ran without being throttled. The decisive test: is a real
    # account still reachable after all those failures?
    real = ctx.post(
        "/api/auth/login", json={"username": "carol", "password": "letmein"}
    )
    if real.status_code == 200:
        return Result(
            Verdict.VULNERABLE,
            f"{len(wrong_statuses)} failed attempts did not lock the account — "
            "the sweep ran unimpeded",
        )

    if real.status_code in (429, 423):
        return Result(
            Verdict.FIXED,
            f"the account was locked out after {len(wrong_statuses)} failed "
            f"attempts (HTTP {real.status_code})",
        )

    return Result(
        Verdict.INCONCLUSIVE,
        f"unexpected status after the sweep: HTTP {real.status_code} "
        f"(sweep statuses {wrong_statuses})",
    )
