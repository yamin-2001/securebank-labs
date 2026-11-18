#!/usr/bin/env python3
"""Fix-isolation matrix.

Applies one lab's fix at a time, re-runs the whole harness, and checks that
EXACTLY ONE verdict flipped. This is the test the plan calls for: a fix that
breaks a different lab is a bug in the lab design, not in the learner's work.

Usage:
    python3 scripts/isolation_matrix.py            # all labs
    python3 scripts/isolation_matrix.py 13 15 18   # just these
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERIFY = ROOT / "verify"
# The Maven project lives in backend/, alongside the React app in frontend/.
BACKEND = ROOT / "backend"
JAVA = BACKEND / "src/main/java/com/securebank"

# Each entry: lab id -> (file, old snippet, new snippet).
# The "fixed" snippet replaces the vulnerable branch with the fixed one.
FIXES: dict[int, tuple[str, str, str]] = {}


def _fix(lab_id, path, old, new):
    FIXES[lab_id] = (path, old, new)


# --- Lab 1: enforce account ownership -----------------------------------
_fix(
    1,
    JAVA / "labs/a01/AccountService.java",
    '        if (labs.isEnabled("idor")) {',
    '        if (labs.isEnabled("idor") && false) {',
)

# --- Lab 2: require the ADMIN role --------------------------------------
_fix(
    2,
    JAVA / "security/SecurityConfig.java",
    '                        .requestMatchers("/api/admin/**").authenticated()',
    '                        .requestMatchers("/api/admin/**").hasRole("ADMIN")',
)

# --- Lab 3: allowlist the callback URL ----------------------------------
_fix(
    3,
    JAVA / "labs/a01/SsrfStatementService.java",
    '        if (labs.isEnabled("ssrf")) {',
    '        if (labs.isEnabled("ssrf") && false) {',
)

# --- Lab 4: stop leaking the secrets in the exception message ----------
_fix(
    4,
    JAVA / "labs/a02/DebugLeakController.java",
    '        if (labs.isEnabled("debugtrace")) {',
    '        if (labs.isEnabled("debugtrace") && false) {',
)

# --- Lab 5: no default credentials ---------------------------------------
_fix(
    5,
    JAVA / "labs/a02/AdminPanelController.java",
    '        if (labs.isEnabled("admincreds")) {',
    '        if (labs.isEnabled("admincreds") && false) {',
)

# --- Lab 8: read the secret from the environment ------------------------
_fix(
    8,
    JAVA / "security/JwtKeys.java",
    '        if (labs.isEnabled("jwtsecret")) {\n'
    '            // LAB 8 (VULNERABLE): the secret is a literal in the source tree.',
    '        if (labs.isEnabled("jwtsecret") && false) {\n'
    '            // LAB 8 (VULNERABLE): the secret is a literal in the source tree.',
)

# --- Lab 9: mask the PII ------------------------------------------------
_fix(
    9,
    JAVA / "labs/a04/CryptoLeakController.java",
    '        if (labs.isEnabled("pii")) {',
    '        if (labs.isEnabled("pii") && false) {',
)

# --- Lab 10: parameterise the SQL ---------------------------------------
# Lab 10 lives in two places: the transfer search and the login query.
_fix(
    10,
    JAVA / "labs/a05/InjectionController.java",
    '        if (labs.isEnabled("sqli")) {',
    '        if (labs.isEnabled("sqli") && false) {',
)
FIXES[10] = [FIXES[10], (
    JAVA / "labs/a07/AuthController.java",
    '        if (labs.isEnabled("sqli")) {',
    '        if (labs.isEnabled("sqli") && false) {',
)]

# --- Lab 11: bind the remark as a variable, not an expression -----------
_fix(
    11,
    JAVA / "labs/a05/SstiRemarkController.java",
    '        if (labs.isEnabled("ssti")) {',
    '        if (labs.isEnabled("ssti") && false) {',
)

# --- Lab 12: parse the template, and pass the date as an argument -------
_fix(
    12,
    JAVA / "labs/a05/ReportController.java",
    '        if (labs.isEnabled("ssti")) {',
    '        if (labs.isEnabled("ssti") && false) {',
)
FIXES[12] = [FIXES[12], (
    JAVA / "labs/a05/ReportController.java",
    '        if (labs.isEnabled("cmdinject")) {',
    '        if (labs.isEnabled("cmdinject") && false) {',
)]

# --- Lab 6: take the sensitive files off the web root -------------------
# The fix is to delete the files, so this lab's "edit" is a file operation
# rather than a code edit. The three files are moved aside and put back.
#
# The .git/config fixture lives in a directory named `git-config-fixture`,
# not `.git` — git refuses to track the contents of a nested .git directory,
# so the source tree uses a name the build renames on the way in. See the
# <resource> block in backend/pom.xml.
LAB6_STATIC = BACKEND / "src/main/resources/static"
LAB6_FILES = [
    LAB6_STATIC / ".env",
    LAB6_STATIC / "git-config-fixture",
    LAB6_STATIC / "backup.zip",
]
LAB6_BACKUP = ROOT / ".isolation-lab6-backup"

# The last harness run's output, kept so a failing check can show why.
LAST_HARNESS_OUTPUT: list[str] = []

# ---------------------------------------------------------------------------
# The users seed block in data.sql.
#
# TWO labs touch it, and they have to compose:
#
#   Lab 5 (default admin credentials) — the fix has to rotate the admin's
#         stored password, otherwise `admin / admin` still matches once the
#         controller stops comparing against the literal.
#   Lab 7 (unsalted MD5) — the fix has to re-seed every row with a salted
#         hash.
#
# Both rewrites replace the same block of text, so they cannot both be
# "find the old text and replace it" edits — the second one would not find
# its needle after the first one rewrote it.
#
# So the seed block is managed centrally: the canonical MD5 block below is
# what the file always goes back to, and a lab's fix is expressed as the
# rows it wants in place. `apply_seed_rows` writes them; `revert_seed_rows`
# puts the canonical block back.
# ---------------------------------------------------------------------------

SEED = BACKEND / "src/main/resources/data.sql"

# The seeded users, in the order data.sql lists them. The passwords are the
# shipped ones; Lab 5 rotates the admin's.
SEED_USERS = [
    (1, "admin", "admin", "admin@bank.com", "Site Administrator", "admin"),
    (2, "alice", "password123", "alice@bank.com", "Alice Anderson", "customer"),
    (3, "bob", "qwerty", "bob@bank.com", "Bob Brown", "customer"),
    (4, "carol", "letmein", "carol@bank.com", "Carol Clark", "customer"),
    (5, "dave", "changeme", "dave@bank.com", "Dave Davis", "customer"),
]

# The password the admin gets in Lab 5's fixed state. It has to be something
# the learner could actually have chosen, and the harness never needs it.
LAB5_ADMIN_PASSWORD = "S3cure-Admin-Passw0rd!"


def _seed_row(user_id, username, password_hash, email, full_name, role) -> str:
    # The column padding matches data.sql, so a revert rewrites the file
    # byte for byte instead of leaving it reformatted. The pad widths are
    # derived from the longest value in each column, so they stay right when
    # a lab swaps in a longer hash (PBKDF2 rows are much longer than MD5).
    #
    # The padding sits *outside* the quotes — a padded string literal would
    # change the value ('bob  ' is not 'bob'), and while Postgres would
    # store it verbatim, the seed's own integrity check compares the
    # literal against md5(password), so it must stay clean.
    user_pad = max(len(u[1]) for u in SEED_USERS)
    email_pad = max(len(u[3]) for u in SEED_USERS)
    name_pad = max(len(u[4]) for u in SEED_USERS)
    pad_user = " " * (user_pad - len(username))
    pad_email = " " * (email_pad - len(email))
    pad_name = " " * (name_pad - len(full_name))
    return (
        f"    ({user_id}, '{username}',{pad_user} '{password_hash}', "
        f"'{email}',{pad_email} '{full_name}',{pad_name} '{role}')"
    )


def _seed_block(rows: list[str]) -> str:
    """The rows as they appear inside the INSERT's VALUES list."""
    # Comma separated: without the commas Postgres reads it as one
    # malformed statement ("syntax error at or near '('"). No trailing comma
    # after the last row — Postgres rejects that ("syntax error at or near
    # ON").
    return ",\n".join(rows)


def canonical_seed_block() -> str:
    """The shipped (vulnerable) seed rows: unsalted MD5."""
    rows = []
    for user_id, username, password, email, full_name, role in SEED_USERS:
        rows.append(_seed_row(user_id, username, md5_hex(password), email, full_name, role))
    return _seed_block(rows)


def md5_hex(text: str) -> str:
    """The MD5 of a password, as PasswordHasher.md5Hex() computes it."""
    return hashlib.md5(text.encode()).hexdigest()


def apply_seed_rows(block: str) -> None:
    """Replace the users seed block in data.sql.

    The block is located by its INSERT statement rather than by its exact
    text, so it can be rewritten repeatedly without the needle moving.
    """
    text = SEED.read_text()
    start = text.index("INSERT INTO users (id, username, password_hash,")
    end = text.index("ON CONFLICT (username) DO UPDATE", start)
    SEED.write_text(text[:start] + "INSERT INTO users (id, username, password_hash, email, full_name, role)\nVALUES\n" + block + "\n" + text[end:])


def revert_seed_rows() -> None:
    """Put the shipped MD5 seed rows back."""
    apply_seed_rows(canonical_seed_block())


def lab5_seed_block() -> str:
    """Lab 5's fixed seed: the admin's password has been rotated."""
    rows = []
    for user_id, username, password, email, full_name, role in SEED_USERS:
        if username == "admin":
            password = LAB5_ADMIN_PASSWORD
        rows.append(_seed_row(user_id, username, md5_hex(password), email, full_name, role))
    return _seed_block(rows)


def lab7_seed_block() -> str:
    """Lab 7's fixed seed: every row uses salted PBKDF2."""
    sys.path.insert(0, str(VERIFY / "payloads"))
    from hash_passwords import hash_password  # noqa: PLC0415

    rows = []
    for user_id, username, password, email, full_name, role in SEED_USERS:
        rows.append(
            _seed_row(user_id, username, hash_password(password), email, full_name, role)
        )
    return _seed_block(rows)


# --- Lab 7: hash with PBKDF2 and re-seed the rows -----------------------
_fix(
    7,
    JAVA / "core/PasswordHasher.java",
    '        if (labs.isEnabled("md5hash")) {',
    '        if (labs.isEnabled("md5hash") && false) {',
)

# --- Lab 13: escape the note -------------------------------------------
_fix(
    13,
    JAVA / "labs/a05/NoteRenderer.java",
    """        if (labs.isEnabled("xss")) {
            // LAB 13 (VULNERABLE): raw interpolation. The note becomes markup.
            //
            // FIX: use renderFixed(note) below.
            return "<div class=\\"txn-note\\">" + (note == null ? "" : note) + "</div>";
        }""",
    """        if (false) {
            return "<div class=\\"txn-note\\">" + (note == null ? "" : note) + "</div>";
        }""",
)

# --- Lab 14: validate the amount ----------------------------------------
_fix(
    14,
    JAVA / "labs/a06/TransferService.java",
    "        if (labs.isEnabled(\"negativetransfer\")) {",
    "        if (labs.isEnabled(\"negativetransfer\") && false) {",
)

# --- Lab 15: ignore the role field --------------------------------------
_fix(
    15,
    JAVA / "labs/a06/ProfileController.java",
    "        if (labs.isEnabled(\"massassign\")) {",
    "        if (labs.isEnabled(\"massassign\") && false) {",
)

# --- Lab 16: one indistinguishable message ------------------------------
_fix(
    16,
    JAVA / "labs/a07/AuthController.java",
    "        if (labs.isEnabled(\"userenum\")) {",
    "        if (labs.isEnabled(\"userenum\") && false) {",
)

# --- Lab 17: enforce the attempt budget ---------------------------------
# The fix is three edits: the service refuses once the budget is gone, a
# failed login counts towards it, and a successful login clears it.
# All three are part of the same lab, so the fix table holds a list of
# edits per lab.
#
# Build the list in one go. Appending to FIXES[17] repeatedly would nest
# the list inside itself, and _edits() would then try to unpack a list
# where it expects a (path, old, new) triple.
FIXES[17] = [
    (
        JAVA / "labs/a07/LoginAttemptService.java",
        """        // LAB 17 (VULNERABLE): nothing is counted and nothing is refused.
        //
        // FIX: the two lines below are the fix.
        //
        //   if (isBlocked(username)) {
        //       throw new TooManyAttemptsException(username);
        //   }
        //
        // and call recordFailure(username) on a failed login and
        // recordSuccess(username) on a successful one.""",
        """        if (isBlocked(username)) {
            throw new TooManyAttemptsException(username);
        }""",
    ),
    # The second edit: a failed login counts towards the budget.
    (
        JAVA / "labs/a07/AuthController.java",
        """        // LAB 17: a failed attempt should count towards the account's budget.
        //
        // FIX: attempts.recordFailure(username);""",
        """        // LAB 17: a failed attempt should count towards the account's budget.
        //
        // FIX: attempts.recordFailure(username);
        attempts.recordFailure(username);""",
    ),
    # The third edit: a successful login clears the counter.
    (
        JAVA / "labs/a07/AuthController.java",
        """        // LAB 17: a successful login should clear the account's counter.
        //
        // FIX: attempts.recordSuccess(user.getUsername());""",
        """        // LAB 17: a successful login should clear the account's counter.
        //
        // FIX: attempts.recordSuccess(user.getUsername());
        attempts.recordSuccess(user.getUsername());""",
    ),
]

# --- Lab 18: rotate the session id --------------------------------------
_fix(
    18,
    JAVA / "labs/a07/SessionLoginController.java",
    '        if (labs.isEnabled("sessionfixation")) {',
    '        if (labs.isEnabled("sessionfixation") && false) {',
)

# --- Lab 19: a random reset token ---------------------------------------
_fix(
    19,
    JAVA / "labs/a07/AuthController.java",
    "        if (labs.isEnabled(\"resettoken\")) {",
    "        if (labs.isEnabled(\"resettoken\") && false) {",
)

# --- Lab 20: do not deserialize untrusted bytes -------------------------
# The fix replaces the ObjectInputStream with a data-only parse.
_fix(
    20,
    JAVA / "labs/a08/IntegrityController.java",
    "        if (labs.isEnabled(\"deserialization\")) {",
    "        if (labs.isEnabled(\"deserialization\") && false) {",
)

# --- Lab 21: pin the algorithm and verify the signature -----------------
_fix(
    21,
    JAVA / "security/LabJwtService.java",
    "        if (labs.isEnabled(\"jwtalgnone\") && declaresAlgNone(token)) {",
    "        if (labs.isEnabled(\"jwtalgnone\") && declaresAlgNone(token) && false) {",
)

# --- Lab 22: a server-generated name, outside the web root ---------------
_fix(
    22,
    JAVA / "labs/a08/IntegrityController.java",
    "        if (labs.isEnabled(\"upload\")) {",
    "        if (labs.isEnabled(\"upload\") && false) {",
)

# --- Lab 23: validate the input at the boundary -------------------------
# Two call sites, so two edits.
_fix(
    23,
    JAVA / "labs/a10/VerboseErrorController.java",
    '        if (labs.isEnabled("verboseerror")) {',
    '        if (labs.isEnabled("verboseerror") && false) {',
)
FIXES[23] = [FIXES[23], (
    JAVA / "labs/a10/VerboseErrorController.java",
    '        if (labs.isEnabled("verboseerror") && raw instanceof String) {',
    '        if (labs.isEnabled("verboseerror") && raw instanceof String && false) {',
)]

# --- Lab 24: do not return the deserializer's message -------------------
_fix(
    24,
    JAVA / "labs/a10/CoercionController.java",
    '        if (labs.isEnabled("typecoercion")) {',
    '        if (labs.isEnabled("typecoercion") && false) {',
)

# --- Lab 25: fail closed -------------------------------------------------
# The fix is to return 401 instead of falling through to the default
# identity. The `labs.isEnabled("failopen")` guard goes with it, so the
# default identity can never be reached.
_fix(
    25,
    JAVA / "security/LabAuthFilter.java",
    """        if (userId == null && labs.isEnabled("failopen")
                && header != null && header.startsWith("Bearer ")) {
            userId = 1L;
            role = "admin";
            username = "admin";
        }""",
    """        if (userId == null && labs.isEnabled("failopen") && false
                && header != null && header.startsWith("Bearer ")) {
            userId = 1L;
            role = "admin";
            username = "admin";
        }""",
)


def run_harness() -> dict[int, str]:
    """Run the harness and return {lab_id: verdict}."""
    proc = subprocess.run(
        [sys.executable, str(VERIFY / "run.py"), "--all", "--expect", "vulnerable", "-v"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    LAST_HARNESS_OUTPUT.clear()
    LAST_HARNESS_OUTPUT.append(proc.stdout)
    verdicts: dict[int, str] = {}
    for line in proc.stdout.splitlines():
        match = re.search(r"\bLAB\s+(\d+)\b", line)
        if not match:
            continue
        verdict = line.strip().split()[0]
        verdicts[int(match.group(1))] = verdict
    return verdicts


def build_and_restart() -> bool:
    build = subprocess.run(
        ["./mvnw", "-q", "-o", "clean", "compile"],
        cwd=BACKEND,
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        print(build.stdout[-3000:])
        print(build.stderr[-3000:])
        return False
    restart = subprocess.run(
        ["./scripts/app.sh", "restart"], cwd=ROOT, capture_output=True, text=True
    )
    return restart.returncode == 0


def _edits(lab_id: int) -> list[tuple[Path, str, str]]:
    """The list of (file, old, new) edits that constitute a lab's fix."""
    entry = FIXES[lab_id]
    if isinstance(entry, list):
        return entry
    # A single edit: (path, old, new).
    return [entry]


def apply(lab_id: int) -> None:
    for path, old, new in _edits(lab_id):
        text = path.read_text()
        if old not in text:
            raise SystemExit(f"lab {lab_id}: snippet not found in {path}")
        path.write_text(text.replace(old, new, 1))

    # Lab 6: the fix is to take the files off the web root.
    if lab_id == 6:
        LAB6_BACKUP.mkdir(exist_ok=True)
        for src in LAB6_FILES:
            if src.exists():
                dest = LAB6_BACKUP / src.relative_to(LAB6_STATIC)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(src), str(dest))

    # Lab 5: rotate the admin's stored password. The controller stops
    # comparing against the literal, but `admin / admin` would still match
    # the seeded md5("admin") row, so the seed has to change too.
    if lab_id == 5:
        apply_seed_rows(lab5_seed_block())

    # Lab 7: re-seed every row with salted PBKDF2 hashes.
    if lab_id == 7:
        apply_seed_rows(lab7_seed_block())


def revert(lab_id: int) -> None:
    if lab_id in (5, 7):
        revert_seed_rows()

    if lab_id == 6 and LAB6_BACKUP.exists():
        # Move the tree back. Directories are moved whole; files are moved
        # one by one so a partially-moved backup still restores cleanly.
        for dest in sorted(LAB6_BACKUP.rglob("*"), key=lambda p: len(p.parts)):
            if dest.is_dir():
                continue
            src = LAB6_STATIC / dest.relative_to(LAB6_BACKUP)
            src.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(dest), str(src))
        shutil.rmtree(LAB6_BACKUP, ignore_errors=True)

    for path, old, new in reversed(_edits(lab_id)):
        text = path.read_text()
        if new not in text:
            # Already reverted (or never applied) — nothing to undo.
            continue
        path.write_text(text.replace(new, old, 1))


def check_seed_integrity() -> list[str]:
    """Check that data.sql's seeded hashes really are the users' passwords.

    A seed hash that is not the MD5 of the password means the account cannot
    log in at all — a silent, confusing failure that has nothing to do with
    the lab under test. Catching it here saves a whole matrix run.
    """
    problems = []
    text = SEED.read_text()
    for user_id, username, password, email, full_name, role in SEED_USERS:
        expected = md5_hex(password)
        row = next(
            (
                line
                for line in text.splitlines()
                if line.strip().startswith(f"({user_id}, '{username}',")
            ),
            None,
        )
        if row is None:
            problems.append(f"{username}: no seed row in data.sql")
        elif f"'{expected}'" not in row:
            problems.append(
                f"{username}: the seeded hash is not md5({password!r}) — "
                "this account cannot log in"
            )
    return problems


def main() -> int:
    wanted = [int(a) for a in sys.argv[1:]] or sorted(FIXES)

    problems = check_seed_integrity()
    if problems:
        print("the seed is broken:")
        for problem in problems:
            print(f"  {problem}")
        return 1

    print("building the shipped build...")
    if not build_and_restart():
        print("build failed")
        return 1

    baseline = run_harness()
    bad = [k for k, v in baseline.items() if v != "VULNERABLE"]
    if bad:
        print(f"baseline is not clean — labs not VULNERABLE: {bad}")
        return 1
    print(f"baseline: all {len(baseline)} labs VULNERABLE\n")

    failures = []
    for lab_id in wanted:
        if lab_id not in FIXES:
            print(f"lab {lab_id}: no fix defined")
            continue

        print(f"--- lab {lab_id}: applying the fix ---")
        applied = False
        try:
            apply(lab_id)
            applied = True
            if not build_and_restart():
                print(f"lab {lab_id}: BUILD FAILED")
                failures.append(lab_id)
                continue

            after = run_harness()
            flipped = sorted(
                k for k, v in after.items()
                if baseline.get(k) == "VULNERABLE" and v != "VULNERABLE"
            )
            if flipped == [lab_id]:
                print(f"lab {lab_id}: OK — exactly one verdict flipped (lab {lab_id} "
                      f"-> {after[lab_id]})")
            else:
                print(f"lab {lab_id}: FAIL — flipped {flipped}, expected [{lab_id}]")
                for line in LAST_HARNESS_OUTPUT[-1].splitlines():
                    if f"LAB {lab_id} " in line or (
                        f"LAB {lab_id} " in line and line.strip().startswith("LAB")
                    ):
                        print(f"    {line.strip()}")
                # The detail line follows the verdict line.
                lines = LAST_HARNESS_OUTPUT[-1].splitlines()
                for i, line in enumerate(lines):
                    if f"LAB {lab_id}" in line and "VULNERABLE" in line or \
                       f"LAB {lab_id}" in line and "FIXED" in line:
                        if i + 1 < len(lines):
                            print(f"    {lines[i + 1].strip()}")
                        break
                failures.append(lab_id)
        except Exception as exc:  # noqa: BLE001
            print(f"lab {lab_id}: ERROR — {exc}")
            failures.append(lab_id)
        finally:
            if applied:
                revert(lab_id)

    print()
    if failures:
        print(f"FAILED: {failures}")
        print("restoring the shipped build...")
        build_and_restart()
        return 1

    print("building the shipped build back up...")
    build_and_restart()
    print("all fix-isolation checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
