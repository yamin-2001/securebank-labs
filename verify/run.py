#!/usr/bin/env python3
"""SecureBank verification harness.

Usage
-----
    python3 verify/run.py --list
    python3 verify/run.py --show 1
    python3 verify/run.py --lab 1
    python3 verify/run.py --all
    python3 verify/run.py --all --expect vulnerable   # the shipped build
    python3 verify/run.py --all --expect fixed        # after you fixed them

The harness talks to the running app over HTTP and observes behaviour only.
It never reads application source and never inspects the lab toggles.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from common import BASE_URL, Client, HarnessError, Result, Verdict, wait_for_app  # noqa: E402

MANIFEST = HERE / "manifest.json"
LABS_DIR = HERE / "labs"

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def colour(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{code}{text}{RESET}"


def load_manifest() -> list[dict]:
    with MANIFEST.open() as fh:
        return json.load(fh)["labs"]


def load_module(name: str):
    path = LABS_DIR / f"{name}.py"
    if not path.exists():
        raise HarnessError(f"no lab module at {path}")
    spec = importlib.util.spec_from_file_location(f"labs.{name}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def cmd_list(labs: list[dict]) -> int:
    print(f"{BOLD}SecureBank labs{RESET}  (target: {BASE_URL})\n")
    for lab in labs:
        print(f"  {BOLD}#{lab['id']:<3}{RESET} {lab['owasp']:<5} "
              f"{lab['title']}")
        print(f"       {DIM}{lab['endpoints'][0]}{RESET}")
    print(f"\n  {len(labs)} lab(s). "
          f"{DIM}python3 verify/run.py --show <id> for details{RESET}")
    return 0


def cmd_show(labs: list[dict], lab_id: int) -> int:
    lab = next((l for l in labs if l["id"] == lab_id), None)
    if lab is None:
        print(f"no lab with id {lab_id}")
        return 2
    module = load_module(lab["module"])
    print(f"{BOLD}LAB {lab['id']} — {lab['title']}{RESET}")
    print(f"  OWASP      : {lab['owasp']}  ({lab['severity']})")
    print(f"  Endpoints  : {', '.join(lab['endpoints'])}")
    print(f"  Toggle     : {lab['toggle']}  (arms the lab — it is NOT the fix)")
    print(f"  Fix here   : {lab['fix_location']}")
    for attr, label in (("STEPS", "Exploit steps"), ("AFFECTED", "Affected code")):
        value = getattr(module, attr, None)
        if value:
            print(f"\n{BOLD}{label}:{RESET}\n  {value}")
    print(f"\n{BOLD}Fix:{RESET} see {lab['fix_location']} "
          f"(solutions/SOLUTIONS.md has the full walkthrough)")
    return 0


def run_one(lab: dict, client: Client, expect: str) -> tuple[Verdict, str]:
    module = load_module(lab["module"])
    # A fresh client per lab: the cookie jar must not leak from one lab into
    # the next, or a lab's own state can change another lab's verdict.
    isolated = Client(client.base)
    try:
        result = module.run(isolated)
    except HarnessError as exc:
        return Verdict.INCONCLUSIVE, str(exc)
    except Exception as exc:  # noqa: BLE001 - a broken module must not kill the run
        return Verdict.INCONCLUSIVE, f"{type(exc).__name__}: {exc}"
    finally:
        isolated.session.close()
    return result.verdict, result.detail


def verdict_ok(verdict: Verdict, expect: str) -> bool:
    if verdict is Verdict.INCONCLUSIVE:
        return False
    return verdict.value == expect.upper()


def cmd_run(labs: list[dict], only: int | None, expect: str, verbose: bool) -> int:
    client = Client()
    print(f"{BOLD}SecureBank verification{RESET}")
    print(f"  target   : {client.base}")
    print(f"  expecting: {expect.upper()}\n")

    if not wait_for_app(client, attempts=5, delay=1.0):
        print(colour("  the app is not responding at " + client.base, RED))
        print(f"  {DIM}start it with: ./scripts/app.sh start{RESET}")
        return 2

    selected = [l for l in labs if only is None or l["id"] == only]
    if not selected:
        print(f"no lab with id {only}")
        return 2

    failures = []
    inconclusive = []
    for lab in selected:
        verdict, detail = run_one(lab, client, expect)
        if verdict is Verdict.VULNERABLE:
            mark = colour("VULNERABLE", GREEN if expect == "vulnerable" else RED)
        elif verdict is Verdict.FIXED:
            mark = colour("FIXED", GREEN if expect == "fixed" else RED)
        else:
            mark = colour("INCONCLUSIVE", YELLOW)

        good = verdict_ok(verdict, expect)
        if verdict is Verdict.INCONCLUSIVE:
            inconclusive.append(lab["id"])
        elif not good:
            failures.append(lab["id"])

        print(f"  {mark:<22} LAB {lab['id']:<3} {lab['title']}")
        if verbose or not good:
            print(f"      {DIM}{detail}{RESET}")

    passed = len(selected) - len(failures) - len(inconclusive)
    print()
    if failures or inconclusive:
        print(colour(f"  {passed}/{len(selected)} labs matched the expectation.", YELLOW))
        if failures:
            print(colour(f"  wrong verdict  : {failures}", RED))
        if inconclusive:
            print(colour(f"  inconclusive   : {inconclusive}", YELLOW))
        return 1

    print(colour(f"  all {len(selected)} labs matched the expectation.", GREEN))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="verify/run.py", description="SecureBank lab verification harness"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="list every lab")
    group.add_argument("--show", type=int, metavar="ID", help="show one lab's details")
    group.add_argument("--lab", type=int, metavar="ID", help="run one lab")
    group.add_argument("--all", action="store_true", help="run every lab")
    parser.add_argument(
        "--expect",
        choices=("vulnerable", "fixed"),
        default="vulnerable",
        help="the expected verdict (default: vulnerable)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="always show details")
    args = parser.parse_args()

    labs = load_manifest()

    if args.list:
        return cmd_list(labs)
    if args.show is not None:
        return cmd_show(labs, args.show)
    return cmd_run(labs, args.lab, args.expect, args.verbose)


if __name__ == "__main__":
    sys.exit(main())
