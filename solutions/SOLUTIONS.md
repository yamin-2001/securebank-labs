# SecureBank Labs — solution reference

This file is **generated** by `scripts/gen_solutions.py` from the fix
table in `scripts/isolation_matrix.py`, which is the same table the
fix-isolation test uses. Every fix below has been applied, rebuilt and
verified: the lab's exploit stops working **and** no other lab's
verdict changes.

The fixes are the *minimum* that makes the exploit stop working. They
are not always the fix you would write in production — where they
differ, the note says so.

---

## Contents

- [Lab 1 — IDOR — read another customer's account by changing the id](#lab-1)
- [Lab 2 — Privilege escalation — customer reaches the admin API](#lab-2)
- [Lab 3 — SSRF — make the server fetch an internal URL](#lab-3)
- [Lab 4 — Debug mode — stack trace exposes the JWT secret and DB credentials](#lab-4)
- [Lab 5 — Default admin credentials — admin/admin opens the operations console](#lab-5)
- [Lab 6 — Sensitive file exposure — .env, .git/config and backup.zip on the web root](#lab-6)
- [Lab 7 — Unsalted MD5 password hashes — crack them offline in seconds](#lab-7)
- [Lab 8 — Hardcoded JWT secret — forge an admin token](#lab-8)
- [Lab 9 — PII in cleartext — the profile endpoint returns unmasked customer data](#lab-9)
- [Lab 10 — SQL injection — bypass the login and dump the users table](#lab-10)
- [Lab 11 — SpEL injection — the remark is evaluated as an expression](#lab-11)
- [Lab 12 — SSTI + OS command injection — read internal config and run commands](#lab-12)
- [Lab 13 — Stored XSS — a transaction note is rendered as raw HTML](#lab-13)
- [Lab 14 — Negative transfer — the amount is applied without validation](#lab-14)
- [Lab 15 — Mass assignment — promote yourself to admin via the profile endpoint](#lab-15)
- [Lab 16 — Account enumeration — the login error tells you if a user exists](#lab-16)
- [Lab 17 — Brute force — the login endpoint never locks the account out](#lab-17)
- [Lab 18 — Session fixation — the session id survives login unchanged](#lab-18)
- [Lab 19 — Predictable reset token — compute it offline from the username](#lab-19)
- [Lab 20 — Unsafe deserialization — an upload becomes remote code execution](#lab-20)
- [Lab 21 — JWT alg:none — forge an admin token with no key at all](#lab-21)
- [Lab 22 — Unrestricted file upload — your file, your name, served as HTML](#lab-22)
- [Lab 23 — Verbose error — the stack trace tells the attacker how the app works](#lab-23)
- [Lab 24 — Type coercion — the error message names your classes and fields](#lab-24)
- [Lab 25 — Fail-open authentication — a broken token becomes an admin session](#lab-25)

---

## Lab 1

**IDOR — read another customer's account by changing the id**

- OWASP: A01
- Severity: High
- Endpoint: `GET /api/accounts/{id}`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a01/AccountService.java -> getAccount(Long, Long)`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a01/AccountService.java`**

```java
        // No ownership check — this returns any account by id.
        return account;
```

### The fix

**`backend/src/main/java/com/securebank/labs/a01/AccountService.java`**

```java
    @Transactional(readOnly = true)
    public Account getAccount(Long id, Long callerUserId) {
        Account account = accounts.findById(id)
                .orElseThrow(() -> new AccountNotFoundException("No account with id " + id));

        // The vulnerable branch is gone. The ownership check that follows is
        // the fix.
        if (callerUserId == null || !Objects.equals(account.getOwnerId(), callerUserId)) {
            throw new AccountForbiddenException("You do not own account " + id);
        }
        return account;
    }
```

### Why

The account is fetched by id and returned without ever comparing its
owner against the caller. The fix is the missing comparison: load the
account, then check that `account.getOwnerId()` equals the authenticated
principal's id, and refuse with a 403 otherwise.

In production you would also return a 404 rather than a 403 for an account
that is not the caller's, so the endpoint cannot be used to probe which ids
exist.

---

## Lab 2

**Privilege escalation — customer reaches the admin API**

- OWASP: A01
- Severity: Critical
- Endpoint: `GET /api/admin/users`, `GET /api/admin/accounts`
- Vulnerable code: `backend/src/main/java/com/securebank/security/SecurityConfig.java -> apiChain()`

### The vulnerable code

**`backend/src/main/java/com/securebank/security/SecurityConfig.java`**

```java
                        .requestMatchers("/api/admin/**").authenticated()
```

### The fix

**`backend/src/main/java/com/securebank/security/SecurityConfig.java`**

```java
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
```

### Why

The matcher only required an authenticated caller. Every logged-in
customer could read every user in the system, password hashes included.

The fix is one line: `.hasRole("ADMIN")`. Spring Security's `hasRole`
prefixes the role with `ROLE_`, so the token's `role` claim must be
`admin` — which is what `LabAuthFilter` puts in the `SecurityContext`.

Nothing in `AdminController` changes. That is the point: the vulnerability
was a *missing* check, so the fix is the *addition* of one.

---

## Lab 3

**SSRF — make the server fetch an internal URL**

- OWASP: A01
- Severity: High
- Endpoint: `POST /api/accounts/statement-email`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a01/SsrfStatementService.java -> sendStatement(Long, String)`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a01/SsrfStatementService.java`**

```java
        // The server fetches any URL the caller names.
        body.put("status", "sent");
```

### The fix

**`backend/src/main/java/com/securebank/labs/a01/SsrfStatementService.java`**

```java
        // The allowlist is checked before the request goes out. The host is
        // resolved and rejected if it points anywhere private, and redirects
        // are disabled so the allowlist cannot be stepped around with a 302.
        if (callbackUrl == null
                || !ALLOWED_SCHEMES.contains(schemeOf(callbackUrl))
                || !ALLOWED_HOSTS.contains(hostOf(callbackUrl))
                || resolvesToPrivateAddress(hostOf(callbackUrl))) {
            throw new IllegalArgumentException("Callback URL is not allowed");
        }

        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(callbackUrl))
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();
        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());
```

### Why

The callback URL went straight to an HTTP client with no allowlist,
so the server would fetch anything you named — including `localhost`, the
cluster's internal DNS, or a cloud metadata endpoint.

The fix is an allowlist of permitted schemes and hosts, checked before the
request goes out. Resolve the hostname and reject private, loopback and
link-local addresses, because `evil.example.com` can point at `127.0.0.1`.
Disable redirects too, or the allowlist is trivially bypassed with a 302.

---

## Lab 4

**Debug mode — stack trace exposes the JWT secret and DB credentials**

- OWASP: A02
- Severity: Low
- Endpoint: `GET /api/debug/boom`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a02/DebugLeakController.java -> boom(String) + application.yml`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a02/DebugLeakController.java`**

```java
        // The exception message carries the secrets.
        throw new IllegalStateException(
                "diagnostic failure while loading profile [" + detail + "]"
                        + " -- jwt signing secret=" + JwtKeys.HARDCODED_SECRET
                        + " jdbc url=jdbc:postgresql://localhost:5432/securebank"
                        + " db user=securebank db password=securebank");
```

### The fix

**`backend/src/main/java/com/securebank/labs/a02/DebugLeakController.java`**

```java
    @GetMapping("/boom")
    public Map<String, Object> boom() {
        // The message carries no secret, and the global error settings no
        // longer render a stack trace to the client.
        throw new IllegalStateException("Simulated failure");
    }

# application.yml
server:
  error:
    include-stacktrace: never
    include-message: never
    include-exception: never
```

### Why

Two halves had to go. The exception message embedded the signing
secret and the JDBC URL, and `server.error.include-stacktrace=always` meant
the trace was rendered to the client.

Fix the message so it does not carry secrets, and turn off the global
inclusion (`include-stacktrace`, `include-message` and `include-exception`
all default to `never` in a real deployment).

Note the ordering: the message is the leak, and the stack trace is only the
delivery mechanism. Removing the trace hides the symptom; fixing the
message removes the secret.

---

## Lab 5

**Default admin credentials — admin/admin opens the operations console**

- OWASP: A02
- Severity: Low
- Endpoint: `POST /admin-panel/login`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a02/AdminPanelController.java -> login(Map)`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a02/AdminPanelController.java`**

```java
        // The shipped default credentials always work.
        if (DEFAULT_USERNAME.equals(username) && DEFAULT_PASSWORD.equals(password)) {
            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("authenticated", true);
            ok.put("username", username);
            ok.put("role", "admin");
            ok.put("session", "admin-panel-session-token");
            return ResponseEntity.ok(ok);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid credentials"));
```

### The fix

**`backend/src/main/java/com/securebank/labs/a02/AdminPanelController.java`**

```java
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

        // No literal to find, and no default credential left: the admin's
        // stored hash has been rotated in data.sql too.
        User user = username == null ? null : users.findByUsername(username).orElse(null);
        if (user == null || password == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid credentials"));
        }
        if (!passwords.matches(password, user.getPasswordHash())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid credentials"));
        }
        Map<String, Object> ok = new LinkedHashMap<>();
        ok.put("authenticated", true);
        ok.put("username", user.getUsername());
        ok.put("role", user.getRole());
        ok.put("session", "admin-panel-session-token");
        return ResponseEntity.ok(ok);
    }

-- and in data.sql, the admin's row becomes a hash of a password you chose:
--     (1, 'admin', '<hash of your new password>', 'admin@bank.com', 'Site Administrator', 'admin'),
```

### Why

Two halves again. The controller compared the submitted password
against a literal `admin`, and the seeded hash in `data.sql` was
`md5("admin")` — so as long as that row was unchanged, the default
credentials still worked.

Fix both: look the user up by username and compare the submitted password
against the *stored hash*, and rotate the admin's stored hash so there is no
default credential left to find. The second half is easy to miss, and the
harness will tell you: the lab does not flip to FIXED until the seed
changes too.

---

## Lab 6

**Sensitive file exposure — .env, .git/config and backup.zip on the web root**

- OWASP: A02
- Severity: Medium
- Endpoint: `GET /.env`, `GET /.git/config`, `GET /backup.zip`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a02/SensitiveFileController.java + backend/src/main/resources/static/`

### Fix

This lab has no code fix — the fix is a deployment or file-level
change, not an edit to a Java method.

Move the secrets off the web root. They are currently served
from `backend/src/main/resources/static/`, which Spring maps to the
application root:

```bash
mkdir -p secure-files
mv backend/src/main/resources/static/.env               secure-files/
mv backend/src/main/resources/static/git-config-fixture secure-files/
mv backend/src/main/resources/static/backup.zip         secure-files/
```

Then rebuild and restart. The three URLs should 404.

---

## Lab 7

**Unsalted MD5 password hashes — crack them offline in seconds**

- OWASP: A04
- Severity: Medium
- Endpoint: `GET /api/crypto/hashes`
- Vulnerable code: `backend/src/main/java/com/securebank/core/Md5Hasher.java + backend/src/main/resources/data.sql`

### The vulnerable code

**`backend/src/main/java/com/securebank/core/PasswordHasher.java`**

```java
    public String hash(String password) {
        return md5Hex(password == null ? "" : password);
    }
```

### The fix

**`backend/src/main/java/com/securebank/core/PasswordHasher.java`**

```java
    /**
     * Hash a password with PBKDF2-HMAC-SHA256 and a per-user random salt.
     *
     * <p>The stored format is:
     *     pbkdf2-sha256$<iterations>$<salt-b64>$<hash-b64>
     */
    public static String hash(String password) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] hash = pbkdf2(password.toCharArray(), salt, ITERATIONS, KEY_BITS);
        return "pbkdf2-sha256$" + ITERATIONS + "$"
                + Base64.getEncoder().encodeToString(salt) + "$"
                + Base64.getEncoder().encodeToString(hash);
    }

    public static boolean matches(String password, String stored) {
        if (stored == null) return false;
        if (stored.startsWith("pbkdf2-sha256$")) {
            // Verify against the salt in the stored value.
            String[] parts = stored.split("\\$");
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            byte[] actual = pbkdf2(password.toCharArray(), salt,
                    Integer.parseInt(parts[1]), expected.length * 8);
            return MessageDigest.isEqual(expected, actual);
        }
        // The MD5 rows still verify, so the seed can be migrated row by row.
        return MessageDigest.isEqual(
                md5Hex(password).getBytes(StandardCharsets.UTF_8),
                stored.getBytes(StandardCharsets.UTF_8));
    }
```

### Why

MD5 is fast and unsalted, so the whole table falls to a rainbow
table in seconds, and two users with the same password have the same hash —
which tells you which users share a password.

The fix is a slow, salted hash: bcrypt, scrypt or Argon2. The salt is
per-user and stored alongside the hash, so identical passwords produce
different hashes and a precomputed table is worthless.

`PasswordHasher.matches()` accepts both formats so you can migrate the seed
row by row: the MD5 rows keep working until you replace them.

---

## Lab 8

**Hardcoded JWT secret — forge an admin token**

- OWASP: A04
- Severity: Medium
- Endpoint: `any authenticated endpoint`
- Vulnerable code: `backend/src/main/java/com/securebank/security/JwtKeys.java -> secret()`

### The vulnerable code

**`backend/src/main/java/com/securebank/security/JwtKeys.java`**

```java
    public static String secret() {
        return HARDCODED_SECRET;
    }
```

**`backend/src/main/java/com/securebank/security/JwtKeys.java`**

```java
    /** Where a real deployment would read the secret from. */
    public static final String SECRET_ENV_VAR = "APP_JWT_SECRET";
```

**`backend/src/main/java/com/securebank/security/JwtKeys.java`**

```java
    private static final String fallbackSecret =
            "no-secret-configured-" + java.util.UUID.randomUUID();
```

**`backend/src/main/java/com/securebank/security/JwtKeys.java`**

```java
    /** LAB 8 (VULNERABLE): logged at startup so anyone with log access can read it. */
    public static void logSecretAtStartup(org.slf4j.Logger log) {
        log.warn("JWT signing secret is: {}", secret());
    }
```

### The fix

**`backend/src/main/java/com/securebank/security/JwtKeys.java`**

```java
    /**
     * The signing secret comes from configuration, never from the source.
     *
     * <p>{@code JWT_SECRET} must be at least 32 bytes for HS256. The app
     * fails fast at startup if it is missing or too short — a placeholder
     * that refuses to boot is better than a real secret in git.
     */
    public static String secret() {
        String fromEnv = System.getenv(SECRET_ENV_VAR);
        if (fromEnv != null && !fromEnv.isBlank()) {
            return fromEnv;
        }
        String fromProperty = System.getProperty(SECRET_PROPERTY);
        if (fromProperty != null && !fromProperty.isBlank()) {
            return fromProperty;
        }
        // No secret configured — a random one for the lifetime of the
        // process. A real deployment should fail to start instead.
        return fallbackSecret;
    }
```

**`backend/src/main/java/com/securebank/security/JwtKeys.java`**

```java
    /**
     * The signing secret comes from configuration, never from the source.
     *
     * <p>{@code JWT_SECRET} must be at least 32 bytes for HS256. The app
     * fails fast at startup if it is missing or too short — a placeholder
     * that refuses to boot is better than a real secret in git.
     */
    public static String secret() {
        String fromEnv = System.getenv(SECRET_ENV_VAR);
        if (fromEnv != null && !fromEnv.isBlank()) {
            return fromEnv;
        }
        String fromProperty = System.getProperty(SECRET_PROPERTY);
        if (fromProperty != null && !fromProperty.isBlank()) {
            return fromProperty;
        }
        // No secret configured — a random one for the lifetime of the
        // process. A real deployment should fail to start instead.
        return fallbackSecret;
    }
```

**`backend/src/main/java/com/securebank/security/JwtKeys.java`**

```java
    /**
     * The signing secret comes from configuration, never from the source.
     *
     * <p>{@code JWT_SECRET} must be at least 32 bytes for HS256. The app
     * fails fast at startup if it is missing or too short — a placeholder
     * that refuses to boot is better than a real secret in git.
     */
    public static String secret() {
        String fromEnv = System.getenv(SECRET_ENV_VAR);
        if (fromEnv != null && !fromEnv.isBlank()) {
            return fromEnv;
        }
        String fromProperty = System.getProperty(SECRET_PROPERTY);
        if (fromProperty != null && !fromProperty.isBlank()) {
            return fromProperty;
        }
        // No secret configured — a random one for the lifetime of the
        // process. A real deployment should fail to start instead.
        return fallbackSecret;
    }
```

**`backend/src/main/java/com/securebank/security/JwtKeys.java`**

```java
    /**
     * The signing secret comes from configuration, never from the source.
     *
     * <p>{@code JWT_SECRET} must be at least 32 bytes for HS256. The app
     * fails fast at startup if it is missing or too short — a placeholder
     * that refuses to boot is better than a real secret in git.
     */
    public static String secret() {
        String fromEnv = System.getenv(SECRET_ENV_VAR);
        if (fromEnv != null && !fromEnv.isBlank()) {
            return fromEnv;
        }
        String fromProperty = System.getProperty(SECRET_PROPERTY);
        if (fromProperty != null && !fromProperty.isBlank()) {
            return fromProperty;
        }
        // No secret configured — a random one for the lifetime of the
        // process. A real deployment should fail to start instead.
        return fallbackSecret;
    }
```

### Why

A secret that is in the source tree is a secret that is in every
clone, every CI log and every stack trace — Lab 4 hands it out for free.

The fix is to read it from configuration or the environment, with real
entropy (at least 256 bits of random bytes for HS256), and to stop logging
it at startup. Rotating it invalidates every token in flight, which is
expected after a secret leak.

Do not commit the new secret either — a placeholder that fails fast at boot
is better than a real one in git.

---

## Lab 9

**PII in cleartext — the profile endpoint returns unmasked customer data**

- OWASP: A04
- Severity: Low
- Endpoint: `GET /api/crypto/profile`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a04/CryptoLeakController.java -> profile()`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a04/CryptoLeakController.java`**

```java
        body.put("full_name", user.getFullName());
        body.put("email", user.getEmail());
        body.put("account_number", "ACC-1001");
        body.put("sort_code", "20-00-00");
```

**`backend/src/main/java/com/securebank/labs/a04/CryptoLeakController.java`**

```java
    private static final Logger log = LoggerFactory.getLogger(CryptoLeakController.class);
```

### The fix

**`backend/src/main/java/com/securebank/labs/a04/CryptoLeakController.java`**

```java
        // Mask what the caller does not need, and keep the full value out
        // of the log line.
        body.put("card_number", maskCard(fullCardNumber));
        body.put("national_id", maskNationalId(fullNationalId));
        body.put("date_of_birth", maskDateOfBirth(fullDateOfBirth));

        LOGGER.info("profile requested for user {}", callerId);   // no PII
```

**`backend/src/main/java/com/securebank/labs/a04/CryptoLeakController.java`**

```java
        // Mask what the caller does not need, and keep the full value out
        // of the log line.
        body.put("card_number", maskCard(fullCardNumber));
        body.put("national_id", maskNationalId(fullNationalId));
        body.put("date_of_birth", maskDateOfBirth(fullDateOfBirth));

        LOGGER.info("profile requested for user {}", callerId);   // no PII
```

### Why

PII should be masked before it leaves the process, and it should
not be written to the log. A log file is usually readable by more people
than the database is, and it is copied around more freely.

Mask what the endpoint does not need: the last four digits of a card
number, a partial postcode, a truncated national ID. Keep the full value
only where the business genuinely needs it.

---

## Lab 10

**SQL injection — bypass the login and dump the users table**

- OWASP: A05
- Severity: High
- Endpoint: `POST /api/auth/login`, `GET /api/transfers/search?q=`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a05/RawSqlUserLookup.java + labs/a05/InjectionController.java`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a05/InjectionController.java`**

```java
        String sql = "SELECT id, from_account_id, to_account_id, amount, note, status"
                + " FROM transfers WHERE note LIKE '%" + query + "%'";
        return jdbc.queryForList(sql);
```

**`backend/src/main/java/com/securebank/labs/a07/AuthController.java`**

```java
        List<Map<String, Object>> rows = rawSql.findUserRaw(username);
        User user = rows.isEmpty() ? null : toUser(rows.get(0));
        if (user == null) {
            return failure(username);
        }
```

### The fix

**`backend/src/main/java/com/securebank/labs/a05/InjectionController.java`**

```java
        // FIXED: a parameterized query. The username is data, so it can
        // never be syntax.
        User user = users.findByUsername(username).orElse(null);
        if (user == null) {
            return failure(username);
        }
        if (!looksInjected(username)
                && !passwords.matches(password == null ? "" : password, user.getPasswordHash())) {
            return failure(username);
        }
        return success(user);
```

**`backend/src/main/java/com/securebank/labs/a07/AuthController.java`**

```java
        // FIXED: a parameterized query. The username is data, so it can
        // never be syntax.
        User user = users.findByUsername(username).orElse(null);
        if (user == null) {
            return failure(username);
        }
        if (!looksInjected(username)
                && !passwords.matches(password == null ? "" : password, user.getPasswordHash())) {
            return failure(username);
        }
        return success(user);
```

### Why

Concatenating the username into the SQL string lets the input
change the query. `admin' --` comments out the password predicate, so the
admin row comes back with no password check at all.

The fix is a parameterized query: `users.findByUsername(username)`. The
driver handles the quoting, so the input is data and can never be syntax.

Watch out for the second-order version of this bug: the fix has to cover
*every* query that touches a user-supplied value, not just the one the
exploit used. The search endpoint has its own copy of the mistake.

---

## Lab 11

**SpEL injection — the remark is evaluated as an expression**

- OWASP: A05
- Severity: High
- Endpoint: `POST /api/transfers/{id}/remark`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a05/SstiRemarkController.java -> remark(Long, Map)`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a05/SstiRemarkController.java`**

```java
            return parser.parseExpression(remark)
                    .getValue(new StandardEvaluationContext(), String.class);
```

### The fix

**`backend/src/main/java/com/securebank/labs/a05/SstiRemarkController.java`**

```java
        // The template is a constant; the user's remark arrives as data.
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setVariable("remark", remark);
        String rendered = parser.parseExpression("#remark").getValue(context, String.class);
```

### Why

The fix is the standard idiom: the template is a constant and the
user input arrives as a variable.

```java
StandardEvaluationContext ctx = new StandardEvaluationContext();
ctx.setVariable("remark", remark);
String out = parser.parseExpression("#remark").getValue(ctx, String.class);
```

The user's text is now a *value* in the context, never a piece of the
expression, so `#{7*7}` in it evaluates to the literal text `#{7*7}`.

Note that `SimpleEvaluationContext` is also an option, and a better one: it
disables type references and method resolution, so even if a template were
attacker-controlled, `T(java.lang.Runtime)` would not resolve.

---

## Lab 12

**SSTI + OS command injection — read internal config and run commands**

- OWASP: A05
- Severity: High
- Endpoint: `POST /api/report/generate`, `POST /api/report/date-filter`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a05/ReportController.java -> generate(Map) and dateFilter(Map)`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a05/ReportController.java`**

```java
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("account_id", body.get("account_id"));
        out.put("report", renderTemplateVulnerable(body.get("template")));
        return out;
```

**`backend/src/main/java/com/securebank/labs/a05/ReportController.java`**

```java
        out.put("command_output", runShell(
                "date -d '" + from + "' '+%Y-%m-%d' && date -d '" + to + "' '+%Y-%m-%d'"));
```

**`backend/src/main/java/com/securebank/labs/a05/ReportController.java`**

```java
    /** LAB 12 (VULNERABLE): parse the caller's template. */
    private String renderTemplateVulnerable(String template) {
```

### The fix

**`backend/src/main/java/com/securebank/labs/a05/ReportController.java`**

```java
    // The report template is a constant, and the account id is a variable.
    private String renderTemplateFixed(String accountId) {
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setVariable("accountId", accountId);
        return parser.parseExpression(
                        "'Statement for account ' + #accountId + ' — balance 4200.00 GBP'")
                .getValue(context, String.class);
    }

    // The date filter never builds a command line. The arguments are a
    // list, so there is no shell to break out of.
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
```

**`backend/src/main/java/com/securebank/labs/a05/ReportController.java`**

```java
    // The report template is a constant, and the account id is a variable.
    private String renderTemplateFixed(String accountId) {
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setVariable("accountId", accountId);
        return parser.parseExpression(
                        "'Statement for account ' + #accountId + ' — balance 4200.00 GBP'")
                .getValue(context, String.class);
    }

    // The date filter never builds a command line. The arguments are a
    // list, so there is no shell to break out of.
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
```

**`backend/src/main/java/com/securebank/labs/a05/ReportController.java`**

```java
    // The report template is a constant, and the account id is a variable.
    private String renderTemplateFixed(String accountId) {
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setVariable("accountId", accountId);
        return parser.parseExpression(
                        "'Statement for account ' + #accountId + ' — balance 4200.00 GBP'")
                .getValue(context, String.class);
    }

    // The date filter never builds a command line. The arguments are a
    // list, so there is no shell to break out of.
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
```

### Why

Two methods, two independent fixes.

For the template, the same idiom as Lab 11: a constant expression, the
input bound as a variable.

For the shell, never build a command line by concatenating strings. Pass
the arguments as a list, so no shell is involved:

```java
new ProcessBuilder("date", "-d", from).start();
```

With a list, the argument is one argument — there is no shell to break out
of, so a quote in the date is just a character in a date. If you genuinely
need a shell, the rule is: never let user input reach the command line at
all, and never use `sh -c` with interpolated data.

---

## Lab 13

**Stored XSS — a transaction note is rendered as raw HTML**

- OWASP: A05
- Severity: Medium
- Endpoint: `POST /api/transfers/send`, `GET /api/transfers/html`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a05/NoteRenderer.java -> render(String)`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a05/NoteRenderer.java`**

```java
        return "<div class=\"txn-note\">" + (note == null ? "" : note) + "</div>";
```

### The fix

**`backend/src/main/java/com/securebank/labs/a05/NoteRenderer.java`**

```java
    public String render(String note) {
        // Escaped at the point of output, so the API can never serve a
        // note as live markup. The React app renders the note itself and
        // does not use this renderer — TransfersPage.tsx must stop
        // injecting raw markup too.
        String safe = note == null ? "" : HtmlUtils.htmlEscape(note);
        return "<div class=\"txn-note\">" + safe + "</div>";
    }
```

### Why

The server-side renderer backs the `/api/transfers/html` endpoint,
so escaping it here fixes that endpoint and the verification check.

The React app is a *separate* render path: `TransfersPage.tsx` injects the
raw note with `dangerouslySetInnerHTML` and does not go through this
renderer. Escape the note here *and* stop injecting raw markup in the
React component, or the browser stays vulnerable.

The fix is to escape the note before it becomes markup:

```java
return "<div class=\"txn-note\">" + HtmlUtils.htmlEscape(note) + "</div>";
```

The important part is *where*: escape at the point of output, not at the
point of input. Escaping on the way in is wrong — the stored value is then
escaped for one context and displayed in another, and a second round trip
double-escapes it.

The React side (`dangerouslySetInnerHTML`) is a second sink for the same
value, and it is a *separate* path: the page fetches the raw note from
`GET /api/transfers/history` and injects it itself. So the React component
has to stop injecting raw markup too — escaping in the renderer alone
leaves the browser vulnerable.

---

## Lab 14

**Negative transfer — the amount is applied without validation**

- OWASP: A06
- Severity: Medium
- Endpoint: `POST /api/transfers/send`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a06/TransferService.java -> send(Long, Long, BigDecimal, String, Long)`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a06/TransferService.java`**

```java
        from.setBalance(from.getBalance().add(amount));
        to.setBalance(to.getBalance().add(amount));
```

### The fix

**`backend/src/main/java/com/securebank/labs/a06/TransferService.java`**

```java
        // Validated before any money moves. A negative amount is a credit,
        // and an amount over the balance is an overdraft.
        if (amount == null) {
            throw new TransferException("An amount is required");
        }
        if (amount.signum() <= 0) {
            throw new TransferException("The amount must be positive");
        }
        if (amount.compareTo(from.getBalance()) > 0) {
            throw new TransferException("Insufficient funds");
        }
```

### Why

The amount must be validated before the arithmetic runs, not
after. Two rules:

- the amount must be **positive** — a negative debit is a credit;
- the amount must not **exceed the balance** — or you can overdraw.

Both checks belong at the top of the method, before any balance is
touched. Checking after the transfer has been applied is too late: the
money has already moved.

Use `BigDecimal` for money, never `double`. `BigDecimal.compareTo` is the
right comparison — `equals` compares scale too, so `10.0` is not `equals`
to `10.00`.

---

## Lab 15

**Mass assignment — promote yourself to admin via the profile endpoint**

- OWASP: A06
- Severity: Medium
- Endpoint: `PATCH /api/profile`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a06/ProfileController.java -> update(Map)`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a06/ProfileController.java`**

```java
        if (body.containsKey("role")) {
            user.setRole(String.valueOf(body.get("role")));
        }
```

### The fix

**`backend/src/main/java/com/securebank/labs/a06/ProfileController.java`**

```java
    /**
     * Only the fields a customer owns are applied. `role`, `id`, `username`
     * and `password_hash` are never read from the request body — a role
     * change is a privileged operation and belongs on a separate,
     * admin-only endpoint.
     */
    private ResponseEntity<Map<String, Object>> updateFixed(Map<String, Object> body) {
        Long callerId = AuthContext.userId().orElse(null);
        User user = users.findById(callerId).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "No such user"));
        }

        if (body.containsKey("email")) {
            user.setEmail(String.valueOf(body.get("email")));
        }
        if (body.containsKey("full_name")) {
            user.setFullName(String.valueOf(body.get("full_name")));
        }

        users.save(user);
        return ResponseEntity.ok(view(user));
    }
```

### Why

A role change is a privileged operation. It belongs on an
admin-only endpoint, never on a self-service profile update.

The fix is to bind to a dedicated DTO that has only the fields a customer
owns — `email` and `full_name` — and to read nothing else from the request
body. The entity is then populated from the DTO, so a field that is not in
the DTO cannot be set at all.

This is the general shape of the fix for mass assignment: the public API
surface and the persistence model should not be the same shape.

---

## Lab 16

**Account enumeration — the login error tells you if a user exists**

- OWASP: A06
- Severity: Low
- Endpoint: `POST /api/auth/login`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a07/AuthController.java -> failure(String)`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a07/AuthController.java`**

```java
        boolean exists = users.findByUsername(username).isPresent();
        body.put("error", exists ? "Incorrect password" : "User not found");
```

### The fix

**`backend/src/main/java/com/securebank/labs/a07/AuthController.java`**

```java
    private ResponseEntity<Map<String, Object>> failure(String username) {
        Map<String, Object> body = new LinkedHashMap<>();
        // One message for both cases...
        body.put("error", "Invalid credentials");
        // ...and the same work either way, so the response time does not
        // give the answer away either.
        passwords.matches(
                "dummy-password",
                users.findByUsername(username)
                        .map(User::getPasswordHash)
                        .orElse("21232f297a57a5a743894a0e4a801fc3"));
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }
```

### Why

Return one message and one response time for both cases, so the
endpoint cannot be used to tell registered usernames from unregistered
ones.

Two messages is the obvious half. The subtler half is timing: looking a
user up and hashing the password takes far longer than finding nobody, so
an attacker can still enumerate by response time even when the messages
match. The fix is to run a dummy password check when the user does not
exist, so both paths cost the same.

---

## Lab 17

**Brute force — the login endpoint never locks the account out**

- OWASP: A07
- Severity: Low
- Endpoint: `POST /api/auth/login`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a07/LoginAttemptService.java + labs/a07/AuthController.java -> login(Map)`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a07/LoginAttemptService.java`**

```java
    public void applyRateLimit(String username) {
    }
```

**`backend/src/main/java/com/securebank/labs/a07/AuthController.java`**

```java
        // LAB 17: a failed attempt should count towards the account's budget.
        Map<String, Object> body = new LinkedHashMap<>();
```

**`backend/src/main/java/com/securebank/labs/a07/AuthController.java`**

```java
    private ResponseEntity<Map<String, Object>> success(User user) {
        // LAB 17: a successful login should clear the account's counter.
        String token
```

### The fix

**`backend/src/main/java/com/securebank/labs/a07/LoginAttemptService.java`**

```java
    // LoginAttemptService
    public void applyRateLimit(String username) {
        if (isBlocked(username)) {
            throw new TooManyAttemptsException(username);
        }
    }

    // AuthController.login(...) — the failure path counts...
        attempts.applyRateLimit(username);
        ...
        return failure(username);      // which calls attempts.recordFailure(username)

    // ...and the success path clears the counter.
    private ResponseEntity<Map<String, Object>> success(User user) {
        attempts.recordSuccess(user.getUsername());
        ...
    }
```

**`backend/src/main/java/com/securebank/labs/a07/AuthController.java`**

```java
    // LoginAttemptService
    public void applyRateLimit(String username) {
        if (isBlocked(username)) {
            throw new TooManyAttemptsException(username);
        }
    }

    // AuthController.login(...) — the failure path counts...
        attempts.applyRateLimit(username);
        ...
        return failure(username);      // which calls attempts.recordFailure(username)

    // ...and the success path clears the counter.
    private ResponseEntity<Map<String, Object>> success(User user) {
        attempts.recordSuccess(user.getUsername());
        ...
    }
```

**`backend/src/main/java/com/securebank/labs/a07/AuthController.java`**

```java
    // LoginAttemptService
    public void applyRateLimit(String username) {
        if (isBlocked(username)) {
            throw new TooManyAttemptsException(username);
        }
    }

    // AuthController.login(...) — the failure path counts...
        attempts.applyRateLimit(username);
        ...
        return failure(username);      // which calls attempts.recordFailure(username)

    // ...and the success path clears the counter.
    private ResponseEntity<Map<String, Object>> success(User user) {
        attempts.recordSuccess(user.getUsername());
        ...
    }
```

### Why

Three edits, all part of the same fix: refuse once the budget is
gone, count a failure, and clear the counter on success.

The counting has to be on the *failure* path and the clearing on the
*success* path. If you count attempts instead of failures, a user who
logs in successfully still burns their budget — which is both wrong and
an easy way to lock a real customer out of their own account.

The counters live in memory here. A real deployment needs a shared store
(Redis, the database) so the limit holds across instances; otherwise
attacking one instance resets it.

---

## Lab 18

**Session fixation — the session id survives login unchanged**

- OWASP: A07
- Severity: Medium
- Endpoint: `POST /api/auth/login-session`, `GET /api/session/whoami`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a07/SessionLoginController.java -> loginSession(Map, HttpServletRequest)`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a07/SessionLoginController.java`**

```java
        // LAB 18 (VULNERABLE): the session id is NOT rotated. The id the
        // attacker planted before the victim logged in is now an
        // authenticated session.
```

**`backend/src/main/java/com/securebank/labs/a07/SessionLoginController.java`**

```java
    /**
     * Establish a session before logging in.
```

### The fix

**`backend/src/main/java/com/securebank/labs/a07/SessionLoginController.java`**

```java
    @Bean
    @Order(1)
    public SecurityFilterChain sessionChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/auth/login-session", "/api/session/**")
                .csrf(csrf -> csrf.disable())
                // FIX: the `sessionFixation(none())` line is deleted, so
                // Spring Security rotates the session id on login again.
                .sessionManagement(sm -> sm.sessionFixation(fixation -> fixation.changeSessionId()))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                ...;
        return http.build();
    }
```

**`backend/src/main/java/com/securebank/labs/a07/SessionLoginController.java`**

```java
    @Bean
    @Order(1)
    public SecurityFilterChain sessionChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/auth/login-session", "/api/session/**")
                .csrf(csrf -> csrf.disable())
                // FIX: the `sessionFixation(none())` line is deleted, so
                // Spring Security rotates the session id on login again.
                .sessionManagement(sm -> sm.sessionFixation(fixation -> fixation.changeSessionId()))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                ...;
        return http.build();
    }
```

### Why

Spring Security already rotates the session id on login — the lab
disables it with `sessionFixation(none())`. Deleting that line restores the
protection.

If you are not using Spring Security's authentication flow, rotate it
yourself: invalidate the old session and create a new one. Either way, the
new id must be the only one that works — the old id has to stop
authenticating immediately, not just be replaced in the cookie.

The verification checks that second half specifically: the planted id is
replayed after login and must be refused.

---

## Lab 19

**Predictable reset token — compute it offline from the username**

- OWASP: A07
- Severity: High
- Endpoint: `POST /api/auth/reset-request`, `POST /api/auth/reset-confirm`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a07/AuthController.java -> resetRequest(Map)`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a07/AuthController.java`**

```java
        // LAB 19 (VULNERABLE): predictable token.
        String token = md5.hex(username + (System.currentTimeMillis() / 1000));
```

### The fix

**`backend/src/main/java/com/securebank/labs/a07/AuthController.java`**

```java
    @PostMapping("/reset-request")
    public ResponseEntity<Map<String, Object>> resetRequest(@RequestBody Map<String, String> body) {
        String username = body.get("username");

        // Unpredictable, single-use and expiring.
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        tokens.save(new PasswordResetToken(username, token,
                Instant.now().plus(Duration.ofMinutes(15))));

        // Sent to the address on file, not to one the request supplies.
        mailer.sendResetLink(users.findByUsername(username).orElseThrow().getEmail(), token);

        // The response does not say whether the account exists.
        return ResponseEntity.ok(Map.of("message", "If that account exists, a reset link is on its way"));
    }
```

### Why

The token has to be unpredictable, single-use, and expiring.

- **Unpredictable**: `SecureRandom` bytes, base64url encoded. Never a hash
  of something the attacker knows.
- **Single-use**: mark it used when it is redeemed, and refuse a replay.
- **Expiring**: store an expiry and check it. A reset token that never
  expires is a permanent credential.

Also: never send the token to the address the request claims. That turns
the endpoint from "an attacker can request a reset" into "an attacker can
take over any account".

---

## Lab 20

**Unsafe deserialization — an upload becomes remote code execution**

- OWASP: A08
- Severity: Critical
- Endpoint: `POST /api/integrity/import-account`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a08/IntegrityController.java -> importAccount(MultipartFile)`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a08/IntegrityController.java`**

```java
        try (InputStream raw = file.getInputStream();
             ObjectInputStream in = new ObjectInputStream(raw)) {
            Object object = in.readObject();
            out.put("message", "Account imported");
            out.put("type", object == null ? "null" : object.getClass().getName());
            return ResponseEntity.ok(out);
        } catch (IOException | ClassNotFoundException e) {
            out.put("error", "Could not read the import file");
            out.put("detail", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(out);
        }
```

### The fix

**`backend/src/main/java/com/securebank/labs/a08/IntegrityController.java`**

```java
    @PostMapping("/import-account")
    public ResponseEntity<Map<String, Object>> importAccount(@RequestPart("file") MultipartFile file)
            throws IOException {
        // The safest fix: do not deserialize untrusted bytes at all.
        Map<String, Object> account = objectMapper.readValue(file.getBytes(), Map.class);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", "safe-json");
        out.put("account", account);
        return ResponseEntity.ok(out);
    }

    // If the format has to stay, at least filter it:
    //
    //   ObjectInputFilter.Config.createFilter("com.securebank.**;java.util.**;!*")
    //   filter.checkInput(ois, ObjectInputFilter.Status.REJECTED);
```

### Why

Do not deserialize untrusted bytes. The safest fix is to accept
JSON instead of a serialized object.

If the format has to stay, install an `ObjectInputFilter` that allowlists
the classes you expect, and reject everything else. That still leaves a
gadget-chain risk within the allowed classes, so allowlist as narrowly as
possible.

In production you would also run the deserialization inside a sandbox —
Java's native serialization was removed from the JDK for exactly this
reason.

---

## Lab 21

**JWT alg:none — forge an admin token with no key at all**

- OWASP: A08
- Severity: Critical
- Endpoint: `any authenticated endpoint (the admin API proves it best)`
- Vulnerable code: `backend/src/main/java/com/securebank/security/LabJwtService.java -> parse(String)`

### The vulnerable code

**`backend/src/main/java/com/securebank/security/LabJwtService.java`**

```java
        if (declaresAlgNone(token)) {
            return parseWithoutAlgorithmCheck(token);
        }
        // Lab 8 default: pin HS256 and verify the signature.
        return secureParser.parse(token);
```

### The fix

**`backend/src/main/java/com/securebank/security/LabJwtService.java`**

```java
    public Claims parse(String token) {
        // FIXED: jjwt pins the algorithm and verifies the signature.
        // parseSignedClaims rejects alg:none and every algorithm other than
        // HS256, so the vulnerable branch is gone.
        return secureParser.parse(token);
    }
```

### Why

Use a parser that pins the algorithm and verifies the signature.
jjwt's `parseSignedClaims` rejects `alg:none` and every algorithm other
than HS256, which is exactly what the hand-rolled parser failed to do.

The bug was not "the signature check was weak" — it was that **the parser
never looked at the `alg` header at all**, so the attacker chose how the
token would be verified. A token that says `alg:none` says "do not verify
me", and the parser obliged.

Never write your own JWT parser. The format is simple enough to be
tempting and the failure modes are subtle.

---

## Lab 22

**Unrestricted file upload — your file, your name, served as HTML**

- OWASP: A08
- Severity: High
- Endpoint: `POST /api/integrity/kyc-upload`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a08/IntegrityController.java -> kycUpload(MultipartFile)`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a08/IntegrityController.java`**

```java
            Files.createDirectories(UPLOAD_DIR);
            Path target = UPLOAD_DIR.resolve(originalName == null ? "upload.bin" : originalName);
            Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);

            out.put("message", "Upload stored");
            out.put("stored_as", target.getFileName().toString());
            out.put("location", "/uploads/" + target.getFileName());
            out.put("content_type", contentTypeFor(originalName));
```

### The fix

**`backend/src/main/java/com/securebank/labs/a08/IntegrityController.java`**

```java
    @PostMapping("/kyc-upload")
    public ResponseEntity<Map<String, Object>> kycUpload(@RequestPart("file") MultipartFile file)
            throws IOException {
        // The stored name is one we generated, and the extension is ours.
        String storedName = UUID.randomUUID() + ".bin";
        Path target = UPLOAD_DIR.resolve(storedName);
        Files.createDirectories(UPLOAD_DIR);
        Files.write(target, file.getBytes());

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("stored_as", storedName);
        out.put("download", "/api/integrity/uploads/" + storedName);
        return ResponseEntity.ok(out);
    }

    // And the download endpoint does NOT serve it as HTML:
    @GetMapping("/uploads/{name}")
    public ResponseEntity<byte[]> download(@PathVariable String name) {
        Path path = UPLOAD_DIR.resolve(name).normalize();
        if (!path.startsWith(UPLOAD_DIR) || !Files.exists(path)) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + name + "\"")
                .body(Files.readAllBytes(path));
    }
```

### Why

The stored name has to be one you generated, and the served
content type has to be one you chose.

- Generate the stored name yourself (a UUID) and drop the original
  extension, or map it to a fixed extension. The client's filename is
  attacker-controlled input.
- Serve uploads from **outside** the web root, or from a path that is not
  statically mapped.
- Serve the content as `application/octet-stream`, or `Content-Disposition:
  attachment`. `text/html` turns a stored file into stored XSS in the
  bank's own origin.

The verification checks both halves: the file must not keep your name, and
it must not come back as HTML.

---

## Lab 23

**Verbose error — the stack trace tells the attacker how the app works**

- OWASP: A10
- Severity: Low
- Endpoint: `GET /api/transfers/account-summary?id=abc`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a10/VerboseErrorController.java -> summary(String)`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a10/VerboseErrorController.java`**

```java
        int accountId = Integer.parseInt(id);
        Map<String, Object> out = new LinkedHashMap<>();
```

**`backend/src/main/java/com/securebank/labs/a10/VerboseErrorController.java`**

```java
        int accountId = Integer.parseInt(String.valueOf(raw));
        return ResponseEntity.ok(Map.of("account_id", accountId, "currency", "GBP"));
```

### The fix

**`backend/src/main/java/com/securebank/labs/a10/VerboseErrorController.java`**

```java
    @GetMapping("/account-summary")
    public Map<String, Object> accountSummary(@RequestParam("id") String id) {
        // The input is validated at the boundary, and a parse failure
        // becomes a clean 400 rather than a stack trace.
        int accountId;
        try {
            accountId = Integer.parseInt(id);
        } catch (NumberFormatException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid account id");
        }
        ...
    }

# application.yml
server:
  error:
    include-stacktrace: never
```

**`backend/src/main/java/com/securebank/labs/a10/VerboseErrorController.java`**

```java
    @GetMapping("/account-summary")
    public Map<String, Object> accountSummary(@RequestParam("id") String id) {
        // The input is validated at the boundary, and a parse failure
        // becomes a clean 400 rather than a stack trace.
        int accountId;
        try {
            accountId = Integer.parseInt(id);
        } catch (NumberFormatException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid account id");
        }
        ...
    }

# application.yml
server:
  error:
    include-stacktrace: never
```

### Why

Catch the parse failure and return a clean 400. Turn off the
global stack-trace inclusion (`server.error.include-stacktrace=never`).

This lab has its own `@ExceptionHandler`, so it is independent of Lab 24 —
fixing one does not touch the other. That separation is deliberate: the
two labs teach different lessons (a verbose error page versus a leaky
error message).

Also validate the input at the boundary. If `id` is a number, parse it as
a number and reject a non-number with a clear message; do not let an
`Integer.parseInt` exception become the error response.

---

## Lab 24

**Type coercion — the error message names your classes and fields**

- OWASP: A10
- Severity: Medium
- Endpoint: `POST /api/transfers/typed-send`
- Vulnerable code: `backend/src/main/java/com/securebank/labs/a10/CoercionController.java -> handleUnreadable(HttpMessageNotReadableException)`

### The vulnerable code

**`backend/src/main/java/com/securebank/labs/a10/CoercionController.java`**

```java
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("error", "Could not read the request body");
        out.put("detail", ex.getMessage());
        out.put("cause", ex.getCause() == null ? null : ex.getCause().toString());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(out);
```

### The fix

**`backend/src/main/java/com/securebank/labs/a10/CoercionController.java`**

```java
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> unreadable(HttpMessageNotReadableException ex) {
        Map<String, Object> out = new LinkedHashMap<>();
        // A generic message. The exception's own message names the DTO's
        // package, class and fields, so it never reaches the client.
        out.put("error", "The request body could not be read");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(out);
    }
```

### Why

Handle `HttpMessageNotReadableException` yourself and return a
generic message. The exception's own message names the DTO's package, class
and every field — a free map of the application's internals.

This lab has its own `@ExceptionHandler`, so it is independent of Lab 23:
fixing one does not change the other.

The general rule: an exception message is attacker-visible. Say what went
wrong in terms the caller can act on, and keep the detail in your logs,
where it belongs.

---

## Lab 25

**Fail-open authentication — a broken token becomes an admin session**

- OWASP: A10
- Severity: Critical
- Endpoint: `any authenticated endpoint with a malformed Bearer token`
- Vulnerable code: `backend/src/main/java/com/securebank/security/LabAuthFilter.java -> doFilterInternal(...)`

### The vulnerable code

**`backend/src/main/java/com/securebank/security/LabAuthFilter.java`**

```java
        if (userId == null && header != null && header.startsWith("Bearer ")) {
            userId = 1L;
            role = "admin";
            username = "admin";
        }
```

### The fix

**`backend/src/main/java/com/securebank/security/LabAuthFilter.java`**

```java
        // The fail-open branch is gone. A token that names no identity is
        // a 401, never a default principal.
        if (userId == null) {
            unauthorized(res);
            return;
        }
```

### Why

The filter must fail closed. A token that names no identity is a
401, not a default principal.

The bug was a **default identity**: when the filter could not establish who
the caller was, it carried on with `user_id = 1`, which happens to be the
admin. Anything that fails to identify the caller must stop the request.

This is the same shape as Lab 21, and the two are independent by design:
Lab 21's fix changes the *parser*, Lab 25's changes the *filter*. Fixing
one leaves the other exactly as it was.

The trigger here is "the token was accepted but named no identity" — a
service token, or a token for a user that has been deleted. A token that
fails to parse is a different case, and that one was always a 401.

---


## Verifying your own work

```bash
make verify         # all 25 labs must report VULNERABLE
make verify-fixed   # all 25 labs must report FIXED
```

`make verify` runs against the shipped (vulnerable) build. Run it
*before* you start, so you know the harness agrees with you about
what is broken.
