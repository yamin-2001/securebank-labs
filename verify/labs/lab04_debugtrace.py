"""LAB 4 (A02 — Security Misconfiguration): stack trace leaks the secrets.

Exploit: GET /api/debug/boom. On the vulnerable build the response body
carries the JWT signing secret, the JDBC URL and the database password,
plus the full stack trace. After the fix — a generic error body and no
secrets in the exception message — none of that is present.
"""

from common import Client, Result, Verdict, contains_any

ID = 4
TITLE = "Debug mode — stack trace exposes the JWT secret and DB credentials"
ENDPOINT = "GET /api/debug/boom"
AFFECTED = "backend/src/main/java/com/securebank/labs/a02/DebugLeakController.java -> boom(String) + application.yml"

SECRET_MARKERS = [
    "hardcoded-jwt-secret",
    "jdbc:postgresql",
    "db password",
    "securebank",
]


def run(ctx: Client) -> Result:
    r = ctx.get("/api/debug/boom?detail=probe")

    if r.status_code == 200:
        return Result(Verdict.INCONCLUSIVE, "the debug endpoint returned 200 — nothing threw")

    text = r.text

    if contains_any(text, SECRET_MARKERS):
        leaked = [m for m in SECRET_MARKERS if m.lower() in text.lower()]
        has_trace = "stackTrace" in text or "at com.securebank" in text
        return Result(
            Verdict.VULNERABLE,
            f"error body leaked {', '.join(leaked)}"
            + (" plus a full stack trace" if has_trace else ""),
        )

    if r.status_code == 404:
        return Result(Verdict.FIXED, "the debug endpoint no longer exists (HTTP 404)")

    if r.status_code == 500:
        return Result(
            Verdict.FIXED,
            f"HTTP 500 but no secrets in the body ({len(text)} bytes)",
        )

    return Result(Verdict.INCONCLUSIVE, f"unexpected HTTP {r.status_code}: {text[:200]}")
