"""The production-shaped fix for each lab.

`isolation_matrix.py` applies each lab's fix as a text substitution and
then rebuilds, so the fix has to be written against the source as it
stands. The snippets there are deliberately minimal — the smallest change
that makes the exploit stop working without disturbing anything else.

This module holds the same fixes as they should be *written*: the
vulnerable code replaced by the real check, in the shape you would ship.
`gen_solutions.py` prints these.

Each entry is the replacement code for the vulnerable snippet — the whole
block, so it can be read as a diff.
"""

REAL_FIXES = {
    1: ("""    @Transactional(readOnly = true)
    public Account getAccount(Long id, Long callerUserId) {
        Account account = accounts.findById(id)
                .orElseThrow(() -> new AccountNotFoundException("No account with id " + id));

        // The vulnerable branch is gone. The ownership check that follows is
        // the fix.
        if (callerUserId == null || !Objects.equals(account.getOwnerId(), callerUserId)) {
            throw new AccountForbiddenException("You do not own account " + id);
        }
        return account;
    }"""),
    2: ("""                .requestMatchers("/api/admin/**").hasRole("ADMIN")"""),
    3: ("""        // The allowlist is checked before the request goes out. The host is
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
                client.send(request, HttpResponse.BodyHandlers.ofString());"""),
    4: ("""    @GetMapping("/boom")
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
    include-exception: never"""),
    5: ("""    @PostMapping("/login")
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
--     (1, 'admin', '<hash of your new password>', 'admin@bank.com', 'Site Administrator', 'admin'),"""),
    7: ("""    /**
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
            String[] parts = stored.split("\\\\$");
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
    }"""),
    8: ("""    /**
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
    }"""),
    9: ("""        // Mask what the caller does not need, and keep the full value out
        // of the log line.
        body.put("card_number", maskCard(fullCardNumber));
        body.put("national_id", maskNationalId(fullNationalId));
        body.put("date_of_birth", maskDateOfBirth(fullDateOfBirth));

        LOGGER.info("profile requested for user {}", callerId);   // no PII"""),
    10: ("""        // FIXED: a parameterized query. The username is data, so it can
        // never be syntax.
        User user = users.findByUsername(username).orElse(null);
        if (user == null) {
            return failure(username);
        }
        if (!looksInjected(username)
                && !passwords.matches(password == null ? "" : password, user.getPasswordHash())) {
            return failure(username);
        }
        return success(user);"""),
    11: ("""        // The template is a constant; the user's remark arrives as data.
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setVariable("remark", remark);
        String rendered = parser.parseExpression("#remark").getValue(context, String.class);"""),
    12: ("""    // The report template is a constant, and the account id is a variable.
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
    }"""),
    13: ("""    public String render(String note) {
        // Escaped at the point of output, so the API can never serve a
        // note as live markup. The React app renders the note itself and
        // does not use this renderer — TransfersPage.tsx must stop
        // injecting raw markup too.
        String safe = note == null ? "" : HtmlUtils.htmlEscape(note);
        return "<div class=\\"txn-note\\">" + safe + "</div>";
    }"""),
    14: ("""        // Validated before any money moves. A negative amount is a credit,
        // and an amount over the balance is an overdraft.
        if (amount == null) {
            throw new TransferException("An amount is required");
        }
        if (amount.signum() <= 0) {
            throw new TransferException("The amount must be positive");
        }
        if (amount.compareTo(from.getBalance()) > 0) {
            throw new TransferException("Insufficient funds");
        }"""),
    15: ("""    /**
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
    }"""),
    16: ("""    private ResponseEntity<Map<String, Object>> failure(String username) {
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
    }"""),
    17: ("""    // LoginAttemptService
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
    }"""),
    18: ("""    @Bean
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
    }"""),
    19: ("""    @PostMapping("/reset-request")
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
    }"""),
    20: ("""    @PostMapping("/import-account")
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
    //   filter.checkInput(ois, ObjectInputFilter.Status.REJECTED);"""),
    21: ("""    public Claims parse(String token) {
        // FIXED: jjwt pins the algorithm and verifies the signature.
        // parseSignedClaims rejects alg:none and every algorithm other than
        // HS256, so the vulnerable branch is gone.
        return secureParser.parse(token);
    }"""),
    22: ("""    @PostMapping("/kyc-upload")
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
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\\"" + name + "\\"")
                .body(Files.readAllBytes(path));
    }"""),
    23: ("""    @GetMapping("/account-summary")
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
    include-stacktrace: never"""),
    24: ("""    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> unreadable(HttpMessageNotReadableException ex) {
        Map<String, Object> out = new LinkedHashMap<>();
        // A generic message. The exception's own message names the DTO's
        // package, class and fields, so it never reaches the client.
        out.put("error", "The request body could not be read");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(out);
    }"""),
    25: ("""        // The fail-open branch is gone. A token that names no identity is
        // a 401, never a default principal.
        if (userId == null) {
            unauthorized(res);
            return;
        }"""),
}
