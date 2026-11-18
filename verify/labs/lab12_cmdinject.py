"""LAB 12 (A05 — Injection): SSTI + OS command injection in the report service.

Two independent exploits, both in /api/report:

1. Template injection — POST /api/report/generate with a template that reads
   the internal secret key out of the root object.
2. Command injection — POST /api/report/date-filter with a from_date that
   breaks out of the date argument and runs `id`.

Either one succeeding means the lab is still vulnerable.
"""

from common import Client, Result, Verdict

ID = 12
TITLE = "SSTI + OS command injection — read internal config and run commands"
ENDPOINT = "POST /api/report/generate, POST /api/report/date-filter"
AFFECTED = "labs/a05/ReportController.java -> generate(Map) and dateFilter(Map)"

TEMPLATE_PAYLOAD = "#root['Config']['secretKey']"

CMD_PAYLOAD = "2024-01-01' && id && echo '"


def run(ctx: Client) -> Result:
    problems = []
    token = ctx.token("alice")

    # --- exploit 1: template injection -------------------------------
    r = ctx.post(
        "/api/report/generate",
        token=token,
        json={"account_id": "1001", "template": TEMPLATE_PAYLOAD},
    )
    if r.status_code == 200:
        try:
            body = r.json()
        except ValueError:
            body = {}
        report = str(body.get("report", ""))
        if "hardcoded-jwt-secret" in report or "jdbc:postgresql" in report:
            problems.append("the template read the internal secret key out of the root object")

    # --- exploit 2: command injection --------------------------------
    r = ctx.post(
        "/api/report/date-filter",
        token=token,
        json={"from_date": CMD_PAYLOAD, "to_date": "2024-12-31"},
    )
    if r.status_code == 200:
        try:
            body = r.json()
        except ValueError:
            body = {}
        out = str(body.get("command_output", ""))
        # `id` prints "uid=..." — the giveaway that the injected command ran.
        if "uid=" in out:
            problems.append("the injected `id` command ran")

    if problems:
        return Result(Verdict.VULNERABLE, "; ".join(problems))

    # Confirm the endpoints still work, so this is not a false "fixed".
    r = ctx.post(
        "/api/report/date-filter",
        token=token,
        json={"from_date": "2024-01-01", "to_date": "2024-12-31"},
    )
    if r.status_code != 200:
        return Result(
            Verdict.INCONCLUSIVE,
            f"the legitimate date filter now returns HTTP {r.status_code}: {r.text[:200]}",
        )

    return Result(
        Verdict.FIXED,
        "both the template injection and the command injection were blocked",
    )
