"""LAB 24 (A10 — Mishandling of Exceptional Conditions): type coercion leaks
the object model.

Exploit: post a transfer whose `amount` is the string "notanumber". The
deserializer cannot coerce it into a BigDecimal and throws — and the error
message names the target type, the field, the value the client sent and the
application's own class path.

After the fix the coercion failure is caught at the boundary and the client
gets a short message with none of that in it.
"""

from common import Client, Result, Verdict

ID = 24
TITLE = "Type coercion — the error message names your classes and fields"
ENDPOINT = "POST /api/transfers/typed-send"
AFFECTED = "backend/src/main/java/com/securebank/labs/a10/CoercionController.java -> handleUnreadable(HttpMessageNotReadableException)"

# The internals that have no business appearing in a client-facing error.
LEAK_MARKERS = (
    "BigDecimal",
    "java.math",
    "com.securebank",
    "org.springframework",
    "TransferRequest",
    "CoercionController",
    "through reference chain",
    "notanumber",
    "HttpMessageNotReadableException",
    "Jackson",
    "tools.jackson",
    "com.fasterxml",
)


def run(ctx: Client) -> Result:
    token = ctx.token("alice")

    r = ctx.post(
        "/api/transfers/typed-send",
        token=token,
        json={
            "from_account_id": 1,
            "to_account_id": 2,
            "amount": "notanumber",
            "note": "lab 24 probe",
        },
    )

    if r.status_code == 200:
        return Result(
            Verdict.INCONCLUSIVE,
            f"the malformed amount was accepted (HTTP 200): {r.text[:200]}",
        )

    body = r.text
    leaked = [m for m in LEAK_MARKERS if m in body]

    if leaked:
        return Result(
            Verdict.VULNERABLE,
            f"the error response leaked {len(leaked)} internal marker(s): "
            + ", ".join(leaked[:5]),
        )

    if r.status_code in (400, 422):
        return Result(
            Verdict.FIXED,
            f"the malformed body was rejected cleanly (HTTP {r.status_code}) with no "
            "internals in the body",
        )

    return Result(
        Verdict.INCONCLUSIVE,
        f"unexpected HTTP {r.status_code}: {body[:200]}",
    )
