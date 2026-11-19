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
# The "fixed" snippet replaces the vulnerable code with the fixed code.
FIXES: dict[int, tuple[str, str, str]] = {}


def _fix(lab_id, path, old, new):
    FIXES[lab_id] = (path, old, new)


# --- Lab 1: enforce account ownership -----------------------------------
_fix(
    1,
    JAVA / "labs/a01/AccountService.java",
    """        // No ownership check — this returns any account by id.
        return account;""",
    """        if (callerUserId == null || !java.util.Objects.equals(account.getOwnerId(), callerUserId)) {
            throw new AccountForbiddenException("You do not own account " + id);
        }
        return account;""",
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
    """        // The server fetches any URL the caller names.
        body.put("status", "sent");""",
    """        if (!isAllowedCallback(uri)) {
            body.put("status", "rejected");
            body.put("error", "callback_url is not allowed");
            return body;
        }

        body.put("status", "sent");""",
)

# --- Lab 4: stop leaking the secrets in the exception message ----------
_fix(
    4,
    JAVA / "labs/a02/DebugLeakController.java",
    """        // The exception message carries the secrets.
        throw new IllegalStateException(
                "diagnostic failure while loading profile [" + detail + "]"
                        + " -- jwt signing secret=" + JwtKeys.HARDCODED_SECRET
                        + " jdbc url=jdbc:postgresql://localhost:5432/securebank"
                        + " db user=securebank db password=securebank");""",
    """        // FIXED: the endpoint is gone. A debug endpoint has no business
        // existing in production, and the detail is not echoed back either.
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "debug endpoint is disabled");
        return ResponseEntity.status(org.springframework.http.HttpStatus.NOT_FOUND).body(body);""",
)

# --- Lab 5: no default credentials ---------------------------------------
_fix(
    5,
    JAVA / "labs/a02/AdminPanelController.java",
    """        // The shipped default credentials always work.
        if (DEFAULT_USERNAME.equals(username) && DEFAULT_PASSWORD.equals(password)) {
            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("authenticated", true);
            ok.put("username", username);
            ok.put("role", "admin");
            ok.put("session", "admin-panel-session-token");
            return ResponseEntity.ok(ok);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid credentials"));""",
    """        User user = username == null ? null : users.findByUsername(username).orElse(null);
        if (user == null || password == null
                || !passwords.matches(password, user.getPasswordHash())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid credentials"));
        }
        Map<String, Object> ok = new LinkedHashMap<>();
        ok.put("authenticated", true);
        ok.put("username", user.getUsername());
        ok.put("role", user.getRole());
        ok.put("session", "admin-panel-session-token");
        return ResponseEntity.ok(ok);""",
)

# --- Lab 8: read the secret from the environment ------------------------
_fix(
    8,
    JAVA / "security/JwtKeys.java",
    """    public static String secret() {
        return HARDCODED_SECRET;
    }""",
    """    public static String secret() {
        String fromEnv = System.getenv(SECRET_ENV_VAR);
        if (fromEnv != null && !fromEnv.isBlank()) {
            return fromEnv;
        }
        String fromProperty = System.getProperty(SECRET_PROPERTY);
        if (fromProperty != null && !fromProperty.isBlank()) {
            return fromProperty;
        }
        return fallbackSecret;
    }""",
)
# Lab 8 also needs the random fallback and the property name.
FIXES[8] = [FIXES[8], (
    JAVA / "security/JwtKeys.java",
    """    /** Where a real deployment would read the secret from. */
    public static final String SECRET_ENV_VAR = "APP_JWT_SECRET";""",
    """    /** Where a real deployment would read the secret from. */
    public static final String SECRET_ENV_VAR = "APP_JWT_SECRET";

    /** The system-property equivalent of {@link #SECRET_ENV_VAR}. */
    public static final String SECRET_PROPERTY = "app.jwt-secret";""",
), (
    JAVA / "security/JwtKeys.java",
    """    private static final String fallbackSecret =
            "no-secret-configured-" + java.util.UUID.randomUUID();""",
    """    private static final String fallbackSecret = randomSecret();

    /** A random secret, held for the lifetime of the process. */
    private static String randomSecret() {
        byte[] bytes = new byte[32];
        new java.security.SecureRandom().nextBytes(bytes);
        return java.util.Base64.getEncoder().encodeToString(bytes);
    }""",
), (
    JAVA / "security/JwtKeys.java",
    """    /** LAB 8 (VULNERABLE): logged at startup so anyone with log access can read it. */
    public static void logSecretAtStartup(org.slf4j.Logger log) {
        log.warn("JWT signing secret is: {}", secret());
    }""",
    """    /** LAB 8 (FIXED): the secret is no longer written to the log. */
    public static void logSecretAtStartup(org.slf4j.Logger log) {
        log.info("JWT signing secret loaded from the environment");
    }""",
)]

# --- Lab 9: mask the PII ------------------------------------------------
_fix(
    9,
    JAVA / "labs/a04/CryptoLeakController.java",
    """        body.put("full_name", user.getFullName());
        body.put("email", user.getEmail());
        body.put("account_number", "ACC-1001");
        body.put("sort_code", "20-00-00");""",
    """        body.put("full_name", maskName(user.getFullName()));
        body.put("email", maskEmail(user.getEmail()));
        body.put("account_number", "ACC-****1001");
        body.put("sort_code", "20-**-**");""",
)

# Lab 9's fix also needs the two masking helpers.
FIXES[9] = [FIXES[9], (
    JAVA / "labs/a04/CryptoLeakController.java",
    """    private static final Logger log = LoggerFactory.getLogger(CryptoLeakController.class);""",
    """    private static final Logger log = LoggerFactory.getLogger(CryptoLeakController.class);

    /** Mask a name: keep the first character, hide the rest. */
    private static String maskName(String name) {
        if (name == null || name.isBlank()) {
            return null;
        }
        return name.charAt(0) + "*".repeat(Math.max(0, name.length() - 1));
    }

    /** Mask an email: keep the first character of the local part. */
    private static String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return null;
        }
        String local = email.substring(0, email.indexOf('@'));
        return local.charAt(0) + "***" + email.substring(email.indexOf('@'));
    }""",
)]

# --- Lab 10: parameterise the SQL ---------------------------------------
# Lab 10 lives in two places: the transfer search and the login query.
_fix(
    10,
    JAVA / "labs/a05/InjectionController.java",
    """        String sql = "SELECT id, from_account_id, to_account_id, amount, note, status"
                + " FROM transfers WHERE note LIKE '%" + query + "%'";
        return jdbc.queryForList(sql);""",
    """        String sql = "SELECT id, from_account_id, to_account_id, amount, note, status"
                + " FROM transfers WHERE note LIKE ?";
        return jdbc.queryForList(sql, "%" + query + "%");""",
)
FIXES[10] = [FIXES[10], (
    JAVA / "labs/a07/AuthController.java",
    """        List<Map<String, Object>> rows = rawSql.findUserRaw(username);
        User user = rows.isEmpty() ? null : toUser(rows.get(0));
        if (user == null) {
            return failure(username);
        }""",
    """        User user = users.findByUsername(username).orElse(null);
        if (user == null) {
            return failure(username);
        }""",
)]

# --- Lab 11: bind the remark as a variable, not an expression -----------
_fix(
    11,
    JAVA / "labs/a05/SstiRemarkController.java",
    """            return parser.parseExpression(remark)
                    .getValue(new StandardEvaluationContext(), String.class);""",
    """            StandardEvaluationContext context = new StandardEvaluationContext();
            context.setVariable("remark", remark);
            return parser.parseExpression("#remark").getValue(context, String.class);""",
)

# --- Lab 12: parse the template, and pass the date as an argument -------
_fix(
    12,
    JAVA / "labs/a05/ReportController.java",
    """        Map<String, Object> out = new LinkedHashMap<>();
        out.put("account_id", body.get("account_id"));
        out.put("report", renderTemplateVulnerable(body.get("template")));
        return out;""",
    """        Map<String, Object> out = new LinkedHashMap<>();
        out.put("account_id", body.get("account_id"));
        out.put("report", renderTemplateFixed(body.get("account_id")));
        return out;""",
)
FIXES[12] = [FIXES[12], (
    JAVA / "labs/a05/ReportController.java",
    """        out.put("command_output", runShell(
                "date -d '" + from + "' '+%Y-%m-%d' && date -d '" + to + "' '+%Y-%m-%d'"));""",
    """        out.put("command_output", runCommand(
                List.of("date", "-d", from, "+%Y-%m-%d")));""",
), (
    # Lab 12's fix needs the two helpers it calls.
    JAVA / "labs/a05/ReportController.java",
    """    /** LAB 12 (VULNERABLE): parse the caller's template. */
    private String renderTemplateVulnerable(String template) {""",
    """    /** The template is a constant; the account id is a variable. */
    private String renderTemplateFixed(String accountId) {
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setVariable("accountId", accountId);
        return parser.parseExpression(
                        "'Statement for account ' + #accountId + ' — balance 4200.00 GBP'")
                .getValue(context, String.class);
    }

    /** Run a command with separate arguments, no shell. */
    private String runCommand(List<String> command) {
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            String output = read(process);
            process.waitFor(10, TimeUnit.SECONDS);
            return output.trim();
        } catch (IOException | InterruptedException e) {
            return "command failed: " + e.getMessage();
        }
    }

    /** LAB 12 (VULNERABLE): parse the caller's template. */
    private String renderTemplateVulnerable(String template) {""",
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
    """    public String hash(String password) {
        return md5Hex(password == null ? "" : password);
    }""",
    """    public String hash(String password) {
        byte[] salt = new byte[16];
        new java.security.SecureRandom().nextBytes(salt);
        String saltB64 = java.util.Base64.getEncoder().encodeToString(salt);
        String hash = pbkdf2(password == null ? "" : password, saltB64);
        return "pbkdf2-sha256$" + 100_000 + "$" + saltB64 + "$" + hash;
    }""",
)

# --- Lab 13: escape the note -------------------------------------------
_fix(
    13,
    JAVA / "labs/a05/NoteRenderer.java",
    """        return "<div class=\\"txn-note\\">" + (note == null ? "" : note) + "</div>";""",
    """        String escaped = org.springframework.web.util.HtmlUtils.htmlEscape(note == null ? "" : note);
        return "<div class=\\"txn-note\\">" + escaped + "</div>";""",
)

# --- Lab 14: validate the amount ----------------------------------------
_fix(
    14,
    JAVA / "labs/a06/TransferService.java",
    """        from.setBalance(from.getBalance().add(amount));
        to.setBalance(to.getBalance().add(amount));""",
    """        if (amount == null) {
            throw new TransferException("Amount is required");
        }
        if (amount.signum() <= 0) {
            throw new TransferException("Amount must be positive");
        }
        if (java.util.Objects.equals(fromAccountId, toAccountId)) {
            throw new TransferException("Cannot transfer to the same account");
        }
        if (from.getBalance().compareTo(amount) < 0) {
            throw new TransferException("Insufficient funds");
        }

        from.setBalance(from.getBalance().subtract(amount));
        to.setBalance(to.getBalance().add(amount));""",
)

# --- Lab 15: ignore the role field --------------------------------------
_fix(
    15,
    JAVA / "labs/a06/ProfileController.java",
    """        if (body.containsKey("role")) {
            user.setRole(String.valueOf(body.get("role")));
        }""",
    """        // `role` is never read from the request body — a role change is a
        // privileged operation and belongs on a separate, admin-only
        // endpoint.""",
)

# --- Lab 16: one indistinguishable message ------------------------------
_fix(
    16,
    JAVA / "labs/a07/AuthController.java",
    """        boolean exists = users.findByUsername(username).isPresent();
        body.put("error", exists ? "Incorrect password" : "User not found");""",
    """        body.put("error", "Invalid credentials");""",
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
        """    public void applyRateLimit(String username) {
    }""",
        """    public void applyRateLimit(String username) {
        if (isBlocked(username)) {
            throw new TooManyAttemptsException(username);
        }
    }""",
    ),
    # The second edit: a failed login counts towards the budget.
    (
        JAVA / "labs/a07/AuthController.java",
        """        // LAB 17: a failed attempt should count towards the account's budget.
        Map<String, Object> body = new LinkedHashMap<>();""",
        """        // LAB 17: a failed attempt should count towards the account's budget.
        attempts.recordFailure(username);
        Map<String, Object> body = new LinkedHashMap<>();""",
    ),
    # The third edit: a successful login clears the counter.
    (
        JAVA / "labs/a07/AuthController.java",
        """    private ResponseEntity<Map<String, Object>> success(User user) {
        // LAB 17: a successful login should clear the account's counter.
        String token""",
        """    private ResponseEntity<Map<String, Object>> success(User user) {
        // LAB 17: a successful login should clear the account's counter.
        attempts.recordSuccess(user.getUsername());
        String token""",
    ),
]

# --- Lab 18: rotate the session id --------------------------------------
_fix(
    18,
    JAVA / "labs/a07/SessionLoginController.java",
    """        // LAB 18 (VULNERABLE): the session id is NOT rotated. The id the
        // attacker planted before the victim logged in is now an
        // authenticated session.
""",
    """        // LAB 18 (FIXED): rotate the id now that the session carries the
        // authenticated attributes. The rotation carries them across to the
        // new session, so the caller stays logged in.
        session = rotateSessionId(request, session);
""",
)
FIXES[18] = [FIXES[18], (
    # Lab 18's fix needs the rotation helper it calls.
    JAVA / "labs/a07/SessionLoginController.java",
    """    /**
     * Establish a session before logging in.""",
    """    /**
     * Rotate the session id at the moment of authentication.
     *
     * <p>The old session is invalidated and a brand-new one is created, with
     * the authenticated attributes carried across.
     */
    private HttpSession rotateSessionId(HttpServletRequest request, HttpSession session) {
        Object userId = session.getAttribute("user_id");
        Object username = session.getAttribute("username");
        Object role = session.getAttribute("role");

        session.invalidate();

        HttpSession fresh = request.getSession(true);
        fresh.setAttribute("user_id", userId);
        fresh.setAttribute("username", username);
        fresh.setAttribute("role", role);
        return fresh;
    }

    /**
     * Establish a session before logging in.""",
)]

# --- Lab 19: a random reset token ---------------------------------------
_fix(
    19,
    JAVA / "labs/a07/AuthController.java",
    """        // LAB 19 (VULNERABLE): predictable token.
        String token = md5.hex(username + (System.currentTimeMillis() / 1000));""",
    """        // LAB 19 (FIXED): unpredictable, single-use and expiring.
        byte[] bytes = new byte[32];
        new java.security.SecureRandom().nextBytes(bytes);
        String token = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(bytes);""",
)

# --- Lab 20: do not deserialize untrusted bytes -------------------------
_fix(
    20,
    JAVA / "labs/a08/IntegrityController.java",
    """        try (InputStream raw = file.getInputStream();
             ObjectInputStream in = new ObjectInputStream(raw)) {
            Object object = in.readObject();
            out.put("message", "Account imported");
            out.put("type", object == null ? "null" : object.getClass().getName());
            return ResponseEntity.ok(out);
        } catch (IOException | ClassNotFoundException e) {
            out.put("error", "Could not read the import file");
            out.put("detail", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(out);
        }""",
    """        try {
            String body = new String(file.getBytes(), java.nio.charset.StandardCharsets.UTF_8);
            out.put("message", "Account imported");
            out.put("mode", "safe-json");
            out.put("bytes", body.length());
            return ResponseEntity.ok(out);
        } catch (IOException e) {
            out.put("error", "Could not read the import file");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(out);
        }""",
)

# --- Lab 21: pin the algorithm and verify the signature -----------------
_fix(
    21,
    JAVA / "security/LabJwtService.java",
    """        if (declaresAlgNone(token)) {
            return parseWithoutAlgorithmCheck(token);
        }
        // Lab 8 default: pin HS256 and verify the signature.
        return secureParser.parse(token);""",
    """        // FIXED: jjwt pins the algorithm and verifies the signature.
        // parseSignedClaims rejects alg:none and every algorithm other than
        // HS256, so the vulnerable branch is gone.
        return secureParser.parse(token);""",
)

# --- Lab 22: a server-generated name, outside the web root ---------------
_fix(
    22,
    JAVA / "labs/a08/IntegrityController.java",
    """            Files.createDirectories(UPLOAD_DIR);
            Path target = UPLOAD_DIR.resolve(originalName == null ? "upload.bin" : originalName);
            Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);

            out.put("message", "Upload stored");
            out.put("stored_as", target.getFileName().toString());
            out.put("location", "/uploads/" + target.getFileName());
            out.put("content_type", contentTypeFor(originalName));""",
    """            String stored = java.util.UUID.randomUUID() + ".bin";
            Path target = Paths.get("var", "kyc", stored);
            Files.createDirectories(target.getParent());
            Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);

            out.put("message", "Upload stored");
            out.put("stored_as", stored);
            out.put("location", "/kyc/" + stored);""",
)

# --- Lab 23: validate the input at the boundary -------------------------
# Two call sites, so two edits.
_fix(
    23,
    JAVA / "labs/a10/VerboseErrorController.java",
    """        int accountId = Integer.parseInt(id);
        Map<String, Object> out = new LinkedHashMap<>();""",
    """        int accountId;
        try {
            accountId = Integer.parseInt(id);
        } catch (NumberFormatException e) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "The account id must be a number"));
        }
        Map<String, Object> out = new LinkedHashMap<>();""",
)
FIXES[23] = [FIXES[23], (
    JAVA / "labs/a10/VerboseErrorController.java",
    """        int accountId = Integer.parseInt(String.valueOf(raw));
        return ResponseEntity.ok(Map.of("account_id", accountId, "currency", "GBP"));""",
    """        int accountId;
        try {
            accountId = Integer.parseInt(String.valueOf(raw));
        } catch (NumberFormatException e) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "The account id must be a number"));
        }
        return ResponseEntity.ok(Map.of("account_id", accountId, "currency", "GBP"));""",
)]

# --- Lab 24: do not return the deserializer's message -------------------
_fix(
    24,
    JAVA / "labs/a10/CoercionController.java",
    """        Map<String, Object> out = new LinkedHashMap<>();
        out.put("error", "Could not read the request body");
        out.put("detail", ex.getMessage());
        out.put("cause", ex.getCause() == null ? null : ex.getCause().toString());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(out);""",
    """        org.slf4j.LoggerFactory.getLogger(CoercionController.class)
                .warn("Rejected a malformed transfer body", ex);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", "The request body was malformed"));""",
)

# --- Lab 25: fail closed -------------------------------------------------
# The fix is to return 401 instead of falling through to the default
# identity.
_fix(
    25,
    JAVA / "security/LabAuthFilter.java",
    """        if (userId == null && header != null && header.startsWith("Bearer ")) {
            userId = 1L;
            role = "admin";
            username = "admin";
        }""",
    """        if (userId == null && header != null && header.startsWith("Bearer ")) {
            unauthorized(res);
            return;
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
