"""LAB 3 (A01 — Broken Access Control): SSRF via the statement callback.

Exploit: POST /api/accounts/statement-email with a callback_url pointing at a
loopback / link-local address. On the vulnerable build the server fetches it
and returns the response body in the JSON reply. After the fix (an allowlist
check on the callback URL) the request is rejected without the server making
the outbound call.
"""

from common import Client, Result, Verdict

ID = 3
TITLE = "SSRF — make the server fetch an internal URL"
ENDPOINT = "POST /api/accounts/statement-email"
AFFECTED = "labs/a01/SsrfStatementService.java -> sendStatement(Long, String)"

# Addresses that only the server itself can reach.
TARGETS = [
    "http://127.0.0.1:8080/api/health",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.1/",
]


def run(ctx: Client) -> Result:
    token = ctx.token("alice")

    for target in TARGETS:
        r = ctx.post(
            "/api/accounts/statement-email",
            token=token,
            json={"account_id": 1, "callback_url": target},
        )
        if r.status_code != 200:
            continue
        try:
            body = r.json()
        except ValueError:
            continue

        if body.get("status") == "rejected":
            return Result(
                Verdict.FIXED,
                f"callback to {target} was rejected — {body.get('error')}",
            )

        # The server made the call and handed back what it found.
        fetched = body.get("callback_body")
        if fetched is not None or body.get("callback_status"):
            status = body.get("callback_status")
            return Result(
                Verdict.VULNERABLE,
                f"server fetched {target} (upstream status {status}) and returned the body",
            )

    return Result(
        Verdict.INCONCLUSIVE,
        "none of the internal targets produced a fetch; the callback feature may be "
        "disabled or unreachable",
    )
