"""LAB 20 (A08 — Software and Data Integrity Failures): unsafe deserialization.

Exploit: upload a serialized Java object whose readObject runs a command.
The server hands the bytes to ObjectInputStream, which instantiates the class
the bytes name and calls readObject while it does — so the command runs
before the server has looked at anything.

The proof is a marker file: the payload's command touches a file, and the
harness checks the filesystem for it. The response body is not evidence,
because a response can be faked by an application that simply ignored the
upload.

After the fix the bytes are parsed as data, so nothing in them can become
code and the marker never appears.
"""

from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from common import Client, Result, Verdict

ID = 20
TITLE = "Unsafe deserialization — an upload becomes remote code execution"
ENDPOINT = "POST /api/integrity/import-account"
AFFECTED = "backend/src/main/java/com/securebank/labs/a08/IntegrityController.java -> importAccount(MultipartFile)"

ROOT = Path(__file__).resolve().parent.parent.parent
# The compiled classes live in the Maven project, which sits in backend/.
CLASSES = ROOT / "backend" / "target" / "classes"
PAYLOAD_SOURCE = ROOT / "verify" / "payloads" / "MakeImportPayload.java"


def run(ctx: Client) -> Result:
    token = ctx.token("alice")

    workdir = Path(tempfile.mkdtemp(prefix="lab20-"))
    marker = workdir / "pwned"
    payload = workdir / "payload.bin"

    command = f"touch {marker}"
    if not _build_payload(payload, command):
        return Result(
            Verdict.INCONCLUSIVE,
            "the serialized payload could not be built (is the project compiled?)",
        )

    with payload.open("rb") as fh:
        r = ctx.post(
            "/api/integrity/import-account",
            token=token,
            files={"file": ("payload.bin", fh, "application/octet-stream")},
        )

    # The command runs during deserialization, which is before the response
    # is written — but the process is started asynchronously, so give it a
    # moment to land.
    for _ in range(20):
        if marker.exists():
            break
        time.sleep(0.1)

    if marker.exists():
        return Result(
            Verdict.VULNERABLE,
            f"the deserialized payload executed its command — the marker "
            f"{marker.name} was created on the server",
        )

    if r.status_code >= 500:
        return Result(
            Verdict.VULNERABLE,
            f"the import failed with HTTP {r.status_code}, which means the bytes "
            "reached the deserializer (the command did not produce a marker)",
        )

    if r.status_code in (400, 415, 422):
        return Result(
            Verdict.FIXED,
            f"the import was refused (HTTP {r.status_code}) and no command ran — "
            "the bytes are parsed as data",
        )

    if r.status_code == 200:
        # The import was accepted, but no command ran. That is only a fix if
        # the bytes were treated as data rather than as a serialized object.
        try:
            payload = r.json()
        except ValueError:
            payload = {}

        if payload.get("mode") == "safe-json" or "type" not in payload:
            return Result(
                Verdict.FIXED,
                "the upload was parsed as data and no command ran — the bytes "
                "cannot name a class",
            )
        return Result(
            Verdict.VULNERABLE,
            f"the bytes were deserialized into {payload.get('type')!r} and no "
            "command ran — the gadget class was still instantiated",
        )

    return Result(
        Verdict.INCONCLUSIVE,
        f"unexpected HTTP {r.status_code}: {r.text[:200]}",
    )


def _build_payload(out: Path, command: str) -> bool:
    """Serialize the gadget with the JVM that already has the app's classes."""
    if not CLASSES.exists():
        return False

    workdir = Path(tempfile.mkdtemp(prefix="lab20-java-"))

    compile_result = subprocess.run(
        ["javac", "-cp", str(CLASSES), "-d", str(workdir), str(PAYLOAD_SOURCE)],
        capture_output=True,
        text=True,
    )
    if compile_result.returncode != 0:
        return False

    run_result = subprocess.run(
        [
            "java",
            "-cp",
            f"{CLASSES}:{workdir}",
            "MakeImportPayload",
            str(out),
            command,
        ],
        capture_output=True,
        text=True,
    )
    return run_result.returncode == 0 and out.exists()
