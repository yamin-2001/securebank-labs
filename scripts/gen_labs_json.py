#!/usr/bin/env python3
"""Regenerate frontend/src/labs.json from verify/manifest.json.

The Labs panel in the running app shows the same metadata as
`verify/run.py --show`. Two hand-maintained copies of that metadata is one
too many: they drifted, and the panel ended up showing an OWASP category
and a severity that contradicted the walkthrough.

The manifest is the source of truth — it drives the harness, `--show`, and
(solutions/SOLUTIONS.md is generated from the same fix table). This script
copies the fields the two documents share, and leaves the rest alone.

Shared fields, copied from the manifest:
    id, slug, owasp, title, severity

Fields the manifest does not carry, kept as they are:
    endpoint  — the panel shows one endpoint; the manifest lists them all.
                The panel's own choices (including "->" for a two-step
                exploit) are worth keeping.
    exploit   — panel-specific prose, unique to labs.json.
    affected  — the panel's rendering of the fix location.
    hint      — panel-specific prose, unique to labs.json.

Severity is lower-cased on the way out: the manifest uses the upper-case
form the CLI prints, and the React component keys its colour styles on the
lower-case form.

Usage:
    python3 scripts/gen_labs_json.py          # rewrite the file
    python3 scripts/gen_labs_json.py --check  # fail if it is out of date
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "verify" / "manifest.json"
TARGET = ROOT / "frontend" / "src" / "labs.json"

# The fields this script owns. Everything else in labs.json is preserved.
SYNCED_FIELDS = ("id", "slug", "owasp", "title", "severity")


def load_manifest() -> list[dict]:
    data = json.loads(MANIFEST.read_text())
    labs = data["labs"] if isinstance(data, dict) else data
    return sorted(labs, key=lambda l: l["id"])


def load_target() -> dict:
    return json.loads(TARGET.read_text())


def sync(manifest: list[dict], target: dict) -> dict:
    """Return a new labs.json with the shared metadata copied from the manifest."""
    by_id = {lab["id"]: lab for lab in target.get("labs", [])}

    merged = []
    for lab in manifest:
        existing = by_id.get(lab["id"], {})
        entry = dict(existing)  # keep the fields the manifest does not carry

        for field in SYNCED_FIELDS:
            entry[field] = lab[field]

        # The manifest prints severity in upper case; the panel styles on lower.
        entry["severity"] = str(lab["severity"]).lower()

        merged.append(entry)

    # Keep any panel-only labs that the manifest does not know about.
    manifest_ids = {lab["id"] for lab in manifest}
    for lab_id, lab in by_id.items():
        if lab_id not in manifest_ids:
            merged.append(lab)
    merged.sort(key=lambda l: l["id"])

    return {"labs": merged}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report drift instead of rewriting the file",
    )
    args = parser.parse_args()

    manifest = load_manifest()
    target = load_target()
    synced = sync(manifest, target)

    if args.check:
        current = target.get("labs", [])
        drifted = []
        for lab in synced["labs"]:
            old = next((l for l in current if l["id"] == lab["id"]), None)
            if old is None:
                drifted.append(lab["id"])
                continue
            for field in SYNCED_FIELDS:
                if old.get(field) != lab.get(field):
                    drifted.append(f"{lab['id']}.{field}")
        if drifted:
            print("frontend/src/labs.json is out of date:", file=sys.stderr)
            for d in drifted:
                print(f"  {d}", file=sys.stderr)
            print("run: python3 scripts/gen_labs_json.py", file=sys.stderr)
            return 1
        print("frontend/src/labs.json is up to date")
        return 0

    TARGET.write_text(json.dumps(synced, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {TARGET.relative_to(ROOT)} ({len(synced['labs'])} labs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
