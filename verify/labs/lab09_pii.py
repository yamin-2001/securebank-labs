"""LAB 9 (A04 — Cryptographic Failures): PII in cleartext responses.

Exploit: GET /api/crypto/profile returns the full unmasked profile — full
name, email, account number, sort code and balance. On the vulnerable build
those values are in the clear. After the fix they are masked.
"""

from common import Client, Result, Verdict

ID = 9
TITLE = "PII in cleartext — the profile endpoint returns unmasked customer data"
ENDPOINT = "GET /api/crypto/profile"
AFFECTED = "backend/src/main/java/com/securebank/labs/a04/CryptoLeakController.java -> profile()"

# Values that must NOT appear in the response once the lab is fixed.
LEAK_MARKERS = {
    "full_name": "Alice Anderson",
    "email": "alice@bank.com",
    "account_number": "ACC-1001",
    "sort_code": "20-00-00",
}


def run(ctx: Client) -> Result:
    r = ctx.get("/api/crypto/profile", token=ctx.token("alice"))
    if r.status_code != 200:
        return Result(
            Verdict.INCONCLUSIVE,
            f"the profile endpoint returned HTTP {r.status_code}: {r.text[:200]}",
        )
    try:
        body = r.json()
    except ValueError:
        return Result(Verdict.INCONCLUSIVE, f"body is not JSON: {r.text[:200]}")
    if not isinstance(body, dict):
        return Result(Verdict.INCONCLUSIVE, "profile body is not an object")

    leaked = [f"{k}={v}" for k, v in LEAK_MARKERS.items() if v in r.text]
    if leaked:
        return Result(
            Verdict.VULNERABLE,
            "unmasked PII in the response: " + ", ".join(leaked),
        )

    return Result(
        Verdict.FIXED,
        "no unmasked PII in the response: "
        + ", ".join(f"{k}={body.get(k)!r}" for k in LEAK_MARKERS),
    )
