"""LAB 11 (A05 — Injection): SpEL template injection.

Exploit: POST /api/transfers/1/remark with a remark of "7*7". On the
vulnerable build the response contains 49 — the user's text was evaluated as
an expression. After the fix the remark is bound as a variable, so the
response contains the literal text "7*7".
"""

from common import Client, Result, Verdict

ID = 11
TITLE = "SpEL injection — the remark is evaluated as an expression"
ENDPOINT = "POST /api/transfers/{id}/remark"
AFFECTED = "backend/src/main/java/com/securebank/labs/a05/SstiRemarkController.java -> remark(Long, Map)"

ARITHMETIC = "7*7"


def run(ctx: Client) -> Result:
    token = ctx.token("alice")

    r = ctx.post(
        "/api/transfers/1/remark",
        token=token,
        json={"remark": ARITHMETIC},
    )
    if r.status_code != 200:
        return Result(
            Verdict.INCONCLUSIVE,
            f"the remark endpoint returned HTTP {r.status_code}: {r.text[:200]}",
        )
    try:
        body = r.json()
    except ValueError:
        return Result(Verdict.INCONCLUSIVE, f"body is not JSON: {r.text[:200]}")

    rendered = str(body.get("rendered", ""))

    if rendered.strip() == "49":
        return Result(
            Verdict.VULNERABLE,
            f"the remark {ARITHMETIC!r} was evaluated to 49 — the template engine "
            "ran the caller's text",
        )

    if ARITHMETIC in rendered:
        return Result(
            Verdict.FIXED,
            f"the remark is now data, not an expression (rendered as {rendered!r})",
        )

    return Result(
        Verdict.INCONCLUSIVE,
        f"unexpected rendered value {rendered!r}",
    )
