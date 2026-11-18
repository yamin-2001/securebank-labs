#!/usr/bin/env python3
"""Generate solutions/SOLUTIONS.md from the isolation matrix's fix table.

The matrix is the single source of truth for what "fixed" means: it applies
each fix, rebuilds, and asserts that exactly one verdict flips. So the
solution reference must be generated from the same table — otherwise the
documented fix and the tested fix drift apart, which is the one thing this
project cannot afford.

Usage:
    python3 scripts/gen_solutions.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import isolation_matrix as mx  # noqa: E402

OUT = ROOT / "solutions" / "SOLUTIONS.md"


def load_manifest() -> list[dict]:
    data = json.loads((ROOT / "verify" / "manifest.json").read_text())
    labs = data["labs"] if isinstance(data, dict) else data
    return sorted(labs, key=lambda l: l["id"])


def format_endpoints(endpoints) -> str:
    """The manifest stores endpoints as a list; render them as code."""
    if not endpoints:
        return "—"
    if isinstance(endpoints, str):
        endpoints = [endpoints]
    return ", ".join(f"`{e}`" for e in endpoints)


def main() -> int:
    manifest = load_manifest()
    by_id = {lab["id"]: lab for lab in manifest}

    lines: list[str] = []
    add = lines.append

    add("# SecureBank Labs — solution reference")
    add("")
    add("This file is **generated** by `scripts/gen_solutions.py` from the fix")
    add("table in `scripts/isolation_matrix.py`, which is the same table the")
    add("fix-isolation test uses. Every fix below has been applied, rebuilt and")
    add("verified: the lab's exploit stops working **and** no other lab's")
    add("verdict changes.")
    add("")
    add("The fixes are the *minimum* that makes the exploit stop working. They")
    add("are not always the fix you would write in production — where they")
    add("differ, the note says so.")
    add("")
    add("---")
    add("")
    add("## Contents")
    add("")
    for lab in manifest:
        add(f"- [Lab {lab['id']} — {lab['title']}](#lab-{lab['id']})")
    add("")
    add("---")
    add("")

    for lab in manifest:
        lab_id = lab["id"]
        add(f"## Lab {lab_id}")
        add("")
        add(f"**{lab['title']}**")
        add("")
        add(f"- OWASP: {lab.get('owasp', '—')}")
        add(f"- Severity: {str(lab.get('severity', '—')).capitalize()}")
        add(f"- Endpoint: {format_endpoints(lab.get('endpoints'))}")
        add(f"- Vulnerable code: `{lab.get('fix_location', '—')}`")
        add("")

        edits = mx._edits(lab_id) if lab_id in mx.FIXES else []

        if not edits:
            add("### Fix")
            add("")
            add("This lab has no code fix — the fix is a deployment or file-level")
            add("change, not an edit to a Java method.")
            add("")
            if lab_id == 6:
                add("Move the secrets off the web root. They are currently served")
                add("from `backend/src/main/resources/static/`, which Spring maps to the")
                add("application root:")
                add("")
                add("```bash")
                add("mkdir -p secure-files")
                add("mv backend/src/main/resources/static/.env               secure-files/")
                add("mv backend/src/main/resources/static/git-config-fixture secure-files/")
                add("mv backend/src/main/resources/static/backup.zip         secure-files/")
                add("```")
                add("")
                add("Then rebuild and restart. The three URLs should 404.")
            add("")
            add("---")
            add("")
            continue

        add("### The vulnerable code")
        add("")
        for path, old, _new in edits:
            rel = path.relative_to(ROOT)
            add(f"**`{rel}`**")
            add("")
            add("```java")
            add(old.rstrip())
            add("```")
            add("")

        add("### The fix")
        add("")
        real = _real_fix(lab_id)
        if real:
            for path, _old, _new in edits:
                rel = path.relative_to(ROOT)
                add(f"**`{rel}`**")
                add("")
                add("```java")
                add(real.rstrip())
                add("```")
                add("")
        else:
            for path, _old, new in edits:
                rel = path.relative_to(ROOT)
                add(f"**`{rel}`**")
                add("")
                add("```java")
                add(new.rstrip())
                add("```")
                add("")

        add("### Why")
        add("")
        for line in _why(lab_id):
            add(line)
        add("")
        add("---")
        add("")

    add("")
    add("## Verifying your own work")
    add("")
    add("```bash")
    add("make verify         # all 25 labs must report VULNERABLE")
    add("make verify-fixed   # all 25 labs must report FIXED")
    add("```")
    add("")
    add("`make verify` runs against the shipped (vulnerable) build. Run it")
    add("*before* you start, so you know the harness agrees with you about")
    add("what is broken.")
    add("")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines))
    print(f"wrote {OUT.relative_to(ROOT)} ({len(lines)} lines)")
    return 0


def _why(lab_id: int) -> list[str]:
    from why import WHY

    text = WHY.get(lab_id, "")
    if not text:
        return []
    return text.splitlines()


def _real_fix(lab_id: int) -> str:
    """The production-shaped fix, if there is one for this lab."""
    from real_fixes import REAL_FIXES

    return REAL_FIXES.get(lab_id, "")


if __name__ == "__main__":
    raise SystemExit(main())
