"""LAB 23 (A10 — Mishandling of Exceptional Conditions): verbose errors.

Exploit: request an account summary with a non-numeric id. The unhandled
NumberFormatException propagates to the global handler, which renders the
stack trace, the exception type and the message back to the client — so the
attacker learns the framework version and the shape of the server's code.

After the fix the input is validated at the boundary and the client gets a
clean 400 with nothing but a short message.
"""

from common import Client, Result, Verdict

ID = 23
TITLE = "Verbose error — the stack trace tells the attacker how the app works"
ENDPOINT = "GET /api/transfers/account-summary?id=abc"
AFFECTED = "backend/src/main/java/com/securebank/labs/a10/VerboseErrorController.java -> summary(String)"

# The markers that mean "a stack trace leaked". Their presence is the whole
# exploit: none of them have any business in an error response.
LEAK_MARKERS = (
    "java.lang.NumberFormatException",
    "at com.securebank",
    "at java.base/",
    "org.springframework",
    "StackTrace",
    "stackTrace",
    "\tat ",
)


def run(ctx: Client) -> Result:
    token = ctx.token("alice")

    r = ctx.get("/api/transfers/account-summary", token=token, params={"id": "abc"})

    if r.status_code == 200:
        return Result(
            Verdict.INCONCLUSIVE,
            f"the invalid id was accepted (HTTP 200): {r.text[:200]}",
        )

    body = r.text
    leaked = [m for m in LEAK_MARKERS if m in body]

    if leaked:
        return Result(
            Verdict.VULNERABLE,
            f"the error response leaked {len(leaked)} internal marker(s): "
            + ", ".join(leaked[:4]),
        )

    if r.status_code in (400, 422):
        return Result(
            Verdict.FIXED,
            f"the invalid id was rejected cleanly (HTTP {r.status_code}) with no "
            "internals in the body",
        )

    return Result(
        Verdict.INCONCLUSIVE,
        f"unexpected HTTP {r.status_code}: {body[:200]}",
    )
