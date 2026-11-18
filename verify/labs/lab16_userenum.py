"""LAB 16 (A06 — Insecure Design): account enumeration via error messages.

Exploit: log in with a non-existent username and with a real username but a
wrong password. On the vulnerable build the two responses differ
("User not found" vs "Incorrect password"), which tells an attacker which
usernames exist. On the fixed build the message is identical either way.
"""

from common import Client, Result, Verdict

ID = 16
TITLE = "Account enumeration — the login error tells you if a user exists"
ENDPOINT = "POST /api/auth/login"
AFFECTED = "backend/src/main/java/com/securebank/labs/a07/AuthController.java -> failure(String)"

MISSING = "notauser"
REAL = "alice"


def run(ctx: Client) -> Result:
    r_missing = ctx.post(
        "/api/auth/login", json={"username": MISSING, "password": "whatever"}
    )
    r_real = ctx.post(
        "/api/auth/login", json={"username": REAL, "password": "definitely-wrong"}
    )

    if r_missing.status_code != 401 or r_real.status_code != 401:
        return Result(
            Verdict.INCONCLUSIVE,
            "a failed login did not return 401 "
            f"(missing user: HTTP {r_missing.status_code}, "
            f"real user: HTTP {r_real.status_code})",
        )

    missing_text = r_missing.text.lower()
    real_text = r_real.text.lower()

    # The classic giveaway: the two messages name different outcomes.
    enumerates = (
        ("user not found" in missing_text and "incorrect password" in real_text)
        or ("incorrect password" in real_text and "user not found" in missing_text)
        or ("not found" in missing_text and "incorrect" in real_text)
    )

    if enumerates:
        return Result(
            Verdict.VULNERABLE,
            "the two failures return different messages — the difference enumerates usernames",
        )

    # A weaker leak: the bodies differ at all.
    if missing_text.strip() != real_text.strip():
        return Result(
            Verdict.VULNERABLE,
            f"the two failures return different bodies: {r_missing.text[:120]!r} "
            f"vs {r_real.text[:120]!r}",
        )

    return Result(
        Verdict.FIXED,
        "both failures return the same message, so usernames cannot be enumerated",
    )
