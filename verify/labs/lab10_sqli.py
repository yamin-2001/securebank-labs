"""LAB 10 (A05 — Injection): SQL injection — login bypass and data dump.

Two exploits, both required to be blocked for the lab to count as fixed:

1. Login bypass — POST /api/auth/login with username "admin' --" and any
   password. The comment removes the password predicate, so the server logs
   us in as admin.
2. Data dump — GET /api/transfers/search?q=' UNION SELECT ... FROM users --
   returns the users table.

Either one succeeding means the lab is still vulnerable.

Note on the UNION payload: the vulnerable query selects six columns
(id, from_account_id, to_account_id, amount, note, status), so the
injected branch has to supply exactly six values of compatible types, or
Postgres rejects the whole statement with a 500. The users data is carried
in the `note` slot, because that is the only TEXT column in the select
list — and the response rows are always labelled with the *transfers*
column names, so the dump can never show up under a "username" key.
"""

from common import Client, Result, Verdict

ID = 10
TITLE = "SQL injection — bypass the login and dump the users table"
ENDPOINT = "POST /api/auth/login, GET /api/transfers/search?q="
AFFECTED = "backend/src/main/java/com/securebank/labs/a05/RawSqlUserLookup.java + backend/src/main/java/com/securebank/labs/a05/InjectionController.java"

# Six columns, matching the select list of the vulnerable query:
#   id(BIGINT) from_account_id(BIGINT) to_account_id(BIGINT)
#   amount(NUMERIC) note(TEXT) status(VARCHAR)
# The seeded username and password_hash are concatenated into `note`.
UNION_PAYLOAD = (
    "' UNION SELECT id, id, id, 0, username || ' | ' || password_hash, role"
    " FROM users--"
)

# A username and its MD5 hash, as they appear in the dumped `note` field.
# Used to tell a dumped user row apart from an ordinary transfer note.
SEEDED_USERS = ("admin", "alice", "bob", "carol", "dave")


def _dumpped_user(note):
    """Return the username if this note is a dumped user row, else None."""
    if not isinstance(note, str):
        return None
    for username in SEEDED_USERS:
        if note.startswith(username + " | "):
            return username
    return None


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
            # The union appends the users table to the transfer rows. The
            # rows are labelled with the transfers column names, so the
            # dumped username shows up inside the "note" field.
            for row in rows:
                if not isinstance(row, dict):
                    continue
                username = _dumpped_user(row.get("note"))
                if username:
                    dump_ok = True
                    problems.append(
                        f"UNION dump returned the users table "
                        f"({username!r} with its hash)"
                    )
                    break
    elif r.status_code == 500:
        # A 500 is not evidence of injection — it means the statement could
        # not be assembled (or something else blew up). Report it honestly
        # rather than claiming the lab is vulnerable.
        return Result(
            Verdict.INCONCLUSIVE,
            f"the UNION payload produced HTTP 500: {r.text[:200]}",
        )

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
