"""LAB 13 (A05 — Injection): stored XSS in transaction notes.

Exploit: send a transfer whose note contains an HTML payload, then read it
back from GET /api/transfers?format=html (the same markup the React UI
injects with dangerouslySetInnerHTML).

The note is rendered by one shared renderer, so the endpoint and the browser
cannot disagree: raw markup means the build is vulnerable, escaped markup
means it is fixed.
"""

from common import Client, Result, Verdict

ID = 13
TITLE = "Stored XSS — a transaction note is rendered as raw HTML"
ENDPOINT = "POST /api/transfers/send, GET /api/transfers/html"
AFFECTED = "labs/a05/NoteRenderer.java -> render(String)"

PAYLOAD = '<img src=x onerror=alert(document.cookie)>'


def run(ctx: Client) -> Result:
    token = ctx.token("alice")

    # Plant the payload in a note. The amount is deliberately tiny: this
    # probe must not disturb the balances, because Lab 14's probe reads
    # them.
    r = ctx.post(
        "/api/transfers/send",
        token=token,
        json={
            "from_account_id": 1,
            "to_account_id": 2,
            "amount": 0.01,
            "note": PAYLOAD,
        },
    )
    if r.status_code != 200:
        return Result(
            Verdict.INCONCLUSIVE,
            f"could not store the note — HTTP {r.status_code}: {r.text[:200]}",
        )

    # Read it back as rendered HTML. The Accept header has to say text/html,
    # or the endpoint refuses to negotiate a representation.
    r = ctx.get(
        "/api/transfers/html",
        token=token,
        headers={"Accept": "text/html"},
    )
    if r.status_code != 200:
        return Result(
            Verdict.INCONCLUSIVE,
            f"the html endpoint returned HTTP {r.status_code}: {r.text[:200]}",
        )

    html = r.text
    if "<img src=x" in html.lower():
        return Result(
            Verdict.VULNERABLE,
            "the stored note came back as live markup — a browser would execute it",
        )
    if "onerror=" in html.lower() and "&lt;" not in html:
        return Result(
            Verdict.VULNERABLE,
            "the stored note came back with an unescaped event handler",
        )

    # Escaped (or absent). Make sure the payload really was stored, so this
    # is not a false "fixed" caused by the note never being saved.
    r = ctx.get("/api/transfers/history", token=token)
    if r.status_code == 200 and PAYLOAD not in r.text:
        return Result(
            Verdict.INCONCLUSIVE,
            "the note was not stored, so the XSS check could not be made",
        )

    return Result(
        Verdict.FIXED,
        "the stored note is HTML-escaped — it is displayed as text, not executed",
    )
