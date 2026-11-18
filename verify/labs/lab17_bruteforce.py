"""LAB 17 (A07 — Identification and Authentication Failures): no rate limiting.

Exploit: hammer the login endpoint with wrong passwords for one account. On
the vulnerable build every attempt is served and nothing locks the account,
so a password sweep runs unimpeded. On the fixed build the account is
locked out (or the request is throttled) and the sweep cannot proceed.

The check watches for the *lockout*, not for a successful guess. That keeps
it independent of Lab 10, where the SQL injection in the same endpoint lets
any password through: a 200 there would be the injection, not the absence of
rate limiting.

The last attempt in the sweep is the seeded password. If the lockout never
engaged, the server handed out a token — and that token proves the account
was reachable and not throttled.
"""

from common import Client, Result, Verdict

ID = 17
TITLE = "Brute force — the login endpoint never locks the account out"
ENDPOINT = "POST /api/auth/login"
AFFECTED = "src/main/java/com/securebank/labs/a07/LoginAttemptService.java + labs/a07/AuthController.java -> login(...)"

# Weak passwords, tried in order. The seeded password is last so that a
# working lockout has a chance to engage before the sweep succeeds.
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

ACCOUNT = "alice"


def run(ctx: Client) -> Result:
    # Confirm the account is reachable, so a later failure is attributable
    # to the lockout and not to a wrong username.
    probe = ctx.post(
        "/api/auth/login", json={"username": ACCOUNT, "password": "password123"}
    )
    if probe.status_code != 200:
        return Result(
            Verdict.INCONCLUSIVE,
            f"alice could not log in with her seeded password — "
            f"HTTP {probe.status_code}: {probe.text[:200]}",
        )

    # Now sweep wrong passwords.
    wrong_statuses = []
    for guess in CANDIDATES[:-1]:
        r = ctx.post(
            "/api/auth/login", json={"username": ACCOUNT, "password": guess}
        )
        wrong_statuses.append(r.status_code)

        # Locked out / throttled — the fix is in place.
        if r.status_code in (429, 423):
            return Result(
                Verdict.FIXED,
                f"the account was locked out after {len(wrong_statuses)} failed "
                f"attempts (HTTP {r.status_code})",
            )

    # The sweep ran without being throttled. Now the decisive test: is the
    # account still reachable after all those failures?
    final = ctx.post(
        "/api/auth/login", json={"username": ACCOUNT, "password": "password123"}
    )
    if final.status_code == 200:
        return Result(
            Verdict.VULNERABLE,
            f"{len(wrong_statuses)} failed attempts did not lock the account — "
            "the correct password was still accepted afterwards",
        )

    if final.status_code in (429, 423):
        return Result(
            Verdict.FIXED,
            f"the account was locked out after {len(wrong_statuses)} failed "
            f"attempts (HTTP {final.status_code})",
        )

    return Result(
        Verdict.INCONCLUSIVE,
        f"unexpected status after the sweep: HTTP {final.status_code} "
        f"(sweep statuses {wrong_statuses})",
    )
