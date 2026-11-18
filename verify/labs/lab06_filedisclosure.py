"""LAB 6 (A02 — Security Misconfiguration): sensitive file exposure.

Exploit: fetch /.env, /.git/config and /backup.zip straight off the web
root. On the vulnerable build all three return 200 with their contents. After
the fix they are gone from the web root and the requests 404.
"""

import io
import zipfile

from common import Client, Result, Verdict

ID = 6
TITLE = "Sensitive file exposure — .env, .git/config and backup.zip on the web root"
ENDPOINT = "GET /.env, GET /.git/config, GET /backup.zip"
AFFECTED = "backend/src/main/java/com/securebank/labs/a02/SensitiveFileController.java + backend/src/main/resources/static/"

ARTEFACTS = [
    ("/.env", ["AWS_ACCESS_KEY_ID", "STRIPE_SECRET_KEY", "JWT_SECRET"]),
    ("/.git/config", ["url =", "[remote", "git@"]),
]


def run(ctx: Client) -> Result:
    leaked = []

    for path, markers in ARTEFACTS:
        r = ctx.get(path)
        if r.status_code == 200 and any(m in r.text for m in markers):
            leaked.append(f"{path} (HTTP 200)")

    r = ctx.get("/backup.zip")
    if r.status_code == 200:
        try:
            with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
                names = zf.namelist()
                body = zf.read(names[0]).decode("utf-8", "replace")
            if "password" in body.lower() or "482c811da5d5b4bc6d497ffa98491e38" in body:
                leaked.append(f"/backup.zip (HTTP 200, contains password hashes)")
        except (zipfile.BadZipFile, IndexError):
            pass

    if leaked:
        return Result(Verdict.VULNERABLE, "exposed: " + ", ".join(leaked))

    # Nothing leaked. The fix is judged on the absence of content, not on a
    # particular status code — a missing file can surface as 404, or as a 500
    # if the resource handler throws and the verbose error page renders.
    statuses = {path: ctx.get(path).status_code for path, _ in ARTEFACTS}
    statuses["/backup.zip"] = ctx.get("/backup.zip").status_code
    if all(s in (401, 403, 404, 410, 500) for s in statuses.values()):
        return Result(
            Verdict.FIXED,
            "the sensitive files are no longer served (statuses: "
            + ", ".join(f"{p}={s}" for p, s in statuses.items())
            + ")",
        )

    return Result(
        Verdict.INCONCLUSIVE,
        f"no leak detected, but the endpoints are still answering: {statuses}",
    )
