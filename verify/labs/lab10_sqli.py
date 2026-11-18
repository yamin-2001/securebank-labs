"""LAB 10 (A05 — Injection): SQL injection — login bypass and data dump.

Two exploits, both required to be blocked for the lab to count as fixed:

1. Login bypass — POST /api/auth/login with username "admin' --" and any
   password. The comment removes the password predicate, so the server logs
   us in as admin.
2. Data dump — GET /api/transfers/search?q=' UNION SELECT ... FROM users --
   returns the users table.

Either one succeeding means the lab is still vulnerable.
"""

from common import Client, Result, Verdict

ID = 10
TITLE = "SQL injection — bypass the login and dump the users table"
ENDPOINT = "POST /api/auth/login, GET /api/transfers/search?q="
AFFECTED = "backend/src/main/java/com/securebank/labs/a05/RawSqlUserLookup.java + backend/src/main/java/com/securebank/labs/a05/InjectionController.java"

# md5 of an empty string, so the payload works regardless of the password.
UNION_PAYLOAD = (
    "' UNION SELECT id, username, password_hash, email, full_name, role, created_at"
    " FROM users--"
)


def run(ctx: Client) -> Result:
    problems = []
    token = ctx.token("alice")

    # --- exploit 1: login bypass -------------------------------------
    r = ctx.post(
        "/api/auth/login",
        json={"username": "admin' --", "password": "anything"},
    )
    bypass_ok = False
    if r.status_code == 200:
        try:
            body = r.json()
        except ValueError:
            body = {}
        if body.get("username") == "admin" or body.get("role") == "admin":
            bypass_ok = True
            problems.append(
                f"login bypass succeeded — logged in as {body.get('username')!r} "
                f"with role {body.get('role')!r}"
            )

    # --- exploit 2: UNION data dump -----------------------------------
    dump_ok = False
    r = ctx.get("/api/transfers/search", params={"q": UNION_PAYLOAD}, token=token)
    if r.status_code == 200:
        try:
            rows = r.json()
        except ValueError:
            rows = None
        if isinstance(rows, list):
            # The union adds the users table to the transfer rows. A username
            # in a row that has no "note" key means the union matched.
            for row in rows:
                if isinstance(row, dict) and "username" in row and "password_hash" in row:
                    dump_ok = True
                    problems.append(
                        f"UNION dump returned the users table "
                        f"({row.get('username')!r} with its hash)"
                    )
                    break

    if problems:
        return Result(Verdict.VULNERABLE, "; ".join(problems))

    if not bypass_ok and not dump_ok:
        return Result(
            Verdict.FIXED,
            "the login bypass and the UNION dump were both blocked",
        )

    return Result(
        Verdict.INCONCLUSIVE,
        "neither exploit matched its expected signature — the endpoints may have "
        "moved or the response shape changed",
    )
