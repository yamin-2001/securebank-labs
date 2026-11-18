"""LAB 18 (A07 — Identification and Authentication Failures): session fixation.

The attack shape: the attacker obtains a session id (by visiting the site
themselves), plants it in the victim's browser — via the stored XSS in Lab 13,
for instance — and then waits for the victim to log in. If the server does
not rotate the id on authentication, the planted id is now an authenticated
session and the attacker can ride it.

So the check is:

1. Obtain a session id, the way the attacker would.
2. Send that id back at the login endpoint.
3. See whether the id survived. If it did, the planted id authenticates.
"""

from common import Client, Result, Verdict

ID = 18
TITLE = "Session fixation — the session id survives login unchanged"
ENDPOINT = "POST /api/auth/login-session, GET /api/session/whoami"
AFFECTED = "labs/a07/SessionLoginController.java -> loginSession(Map, HttpServletRequest)"


def run(ctx: Client) -> Result:
    # A fresh jar, so we control exactly which cookies are sent.
    ctx.session.cookies.clear()

    # --- step 1: the attacker obtains a session id --------------------
    # The attacker visits the site and gets a valid, unauthenticated session
    # id, which they will plant in the victim's browser.
    ctx.get("/api/session/start")

    planted = _cookie_value(ctx, "JSESSIONID")
    if not planted:
        return Result(
            Verdict.INCONCLUSIVE,
            "the server did not issue a JSESSIONID cookie, so the fixation "
            "check could not be made",
        )

    # --- step 2: the victim logs in carrying the planted id ------------
    r = ctx.post(
        "/api/auth/login-session",
        json={"username": "alice", "password": "password123"},
    )
    if r.status_code != 200:
        return Result(
            Verdict.INCONCLUSIVE,
            f"the session login returned HTTP {r.status_code}: {r.text[:200]}",
        )

    try:
        body = r.json()
    except ValueError:
        return Result(Verdict.INCONCLUSIVE, f"the login body is not JSON: {r.text[:200]}")

    issued = str(body.get("session_id", ""))

    # The id was rotated — the fix is in place.
    if issued and issued != planted:
        # And the planted id must no longer authenticate. The jar now holds
        # the NEW id the server issued, so it has to be swapped back to the
        # planted one: that is the id the attacker is holding.
        ctx.session.cookies.clear()
        ctx.session.cookies.set("JSESSIONID", planted)
        r2 = ctx.get("/api/session/whoami")
        if r2.status_code == 200:
            return Result(
                Verdict.VULNERABLE,
                "the id was rotated, but the planted session id still authenticates",
            )
        return Result(
            Verdict.FIXED,
            "the session id was rotated on login and the planted id no longer "
            "authenticates",
        )

    # The id survived. The real test: does the planted id authenticate?
    ctx.session.cookies.clear()
    ctx.session.cookies.set("JSESSIONID", planted)
    r2 = ctx.get("/api/session/whoami")
    if r2.status_code == 200:
        return Result(
            Verdict.VULNERABLE,
            "the planted session id still authenticates after login — the "
            "attacker can hijack the session",
        )

    return Result(
        Verdict.INCONCLUSIVE,
        f"the session id was not rotated (issued {issued!r}) but the planted id "
        f"did not authenticate either (HTTP {r2.status_code}) — the check is "
        "inconclusive",
    )


def _cookie_value(ctx: Client, name: str) -> str | None:
    for cookie in ctx.session.cookies:
        if cookie.name == name:
            return cookie.value
    return None
