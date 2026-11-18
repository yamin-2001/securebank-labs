package com.securebank.labs.a07;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.securebank.core.LabToggles;
import com.securebank.core.Md5Hasher;
import com.securebank.core.PasswordHasher;
import com.securebank.domain.PasswordResetToken;
import com.securebank.domain.User;
import com.securebank.domain.repo.PasswordResetTokenRepository;
import com.securebank.domain.repo.UserRepository;
import com.securebank.labs.a05.RawSqlUserLookup;
import com.securebank.security.LabJwtService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Authentication endpoints.
 *
 * <p>Home to four labs, each with its own fix location and its own toggle:
 * <ul>
 *   <li><strong>LAB 10</strong> (A05) — SQL injection / login bypass</li>
 *   <li><strong>LAB 16</strong> (A06) — account enumeration via error messages</li>
 *   <li><strong>LAB 17</strong> (A07) — no rate limiting</li>
 *   <li><strong>LAB 19</strong> (A07) — predictable password reset token</li>
 * </ul>
 *
 * <p>Each of those labs lives in its own method, so fixing one does not
 * affect the others.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository users;
    private final PasswordResetTokenRepository resetTokens;
    private final RawSqlUserLookup rawSql;
    private final Md5Hasher md5;
    private final PasswordHasher passwords;
    private final LabJwtService jwt;
    private final LabToggles labs;

    public AuthController(UserRepository users, PasswordResetTokenRepository resetTokens,
                          RawSqlUserLookup rawSql,
                          Md5Hasher md5, PasswordHasher passwords,
                          LabJwtService jwt, LabToggles labs) {
        this.users = users;
        this.resetTokens = resetTokens;
        this.rawSql = rawSql;
        this.md5 = md5;
        this.passwords = passwords;
        this.jwt = jwt;
        this.labs = labs;
    }

    /**
     * Log in and receive a bearer token.
     *
     * <p><strong>LAB 10 (VULNERABLE):</strong> the username is concatenated
     * straight into the SQL string. A payload like {@code admin' --} comments
     * out the password check and logs you in as admin.
     *
     * <p><strong>FIX:</strong> use a parameterized query. The vulnerable
     * statement and the parameterized replacement are shown side by side below.
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

        // LAB 17 (VULNERABLE): no rate limiting. A brute-force loop can guess
        // a weak password in seconds.
        //
        // FIX: call a LoginAttemptService before this point and reject the
        // request when the account has exceeded its attempt budget
        // (see labs/a07/LoginAttemptService).

        if (labs.isEnabled("sqli")) {
            // LAB 10 (VULNERABLE): string-concatenated SQL. The username is
            // pasted into the statement, so `admin' --` comments out the
            // rest of the WHERE clause and the admin row is returned with
            // no password check at all.
            //
            // FIX: switch to the parameterized lookup.
            //   User user = users.findByUsername(username).orElse(null);
            //   if (user == null || !passwords.matches(password, user.getPasswordHash())) {
            //       return failure(username);
            //   }
            //
            // Note that the password check itself lives in Java, not in the
            // SQL — so Lab 7 (the hashing) and Lab 10 (the injection) are
            // genuinely independent. Fixing either leaves the other alone.
            List<Map<String, Object>> rows = rawSql.findUserRaw(username);
            User user = rows.isEmpty() ? null : toUser(rows.get(0));
            if (user == null) {
                return failure(username);
            }
            // The SQL comment removed the password predicate, so the password
            // is not actually checked — that IS the vulnerability.
            return success(user);
        }

        // FIXED: parameterised lookup — the payload is treated as data.
        User user = users.findByUsername(username).orElse(null);
        if (user == null || !passwords.matches(password == null ? "" : password, user.getPasswordHash())) {
            return failure(username);
        }
        return success(user);
    }

    /**
     * Map a raw JDBC row (as returned by {@link RawSqlUserLookup}) onto the
     * {@link User} entity.
     */
    @SuppressWarnings("unchecked")
    private User toUser(Object row) {
        Map<String, Object> r = (Map<String, Object>) row;
        User user = new User();
        Object id = r.get("id");
        user.setId(id == null ? null : ((Number) id).longValue());
        user.setUsername((String) r.get("username"));
        user.setPasswordHash((String) r.get("password_hash"));
        user.setEmail((String) r.get("email"));
        user.setFullName((String) r.get("full_name"));
        user.setRole((String) r.get("role"));
        Object created = r.get("created_at");
        if (created instanceof java.sql.Timestamp ts) {
            user.setCreatedAt(ts.toInstant());
        }
        return user;
    }

    /**
     * LAB 16 (VULNERABLE): the error message reveals whether the username
     * exists — "User not found" versus "Incorrect password".
     *
     * <p>FIX: return one indistinguishable message for both cases, and
     * equalise the response time.
     */
    private ResponseEntity<Map<String, Object>> failure(String username) {
        Map<String, Object> body = new LinkedHashMap<>();
        if (labs.isEnabled("userenum")) {
            boolean exists = users.findByUsername(username).isPresent();
            body.put("error", exists ? "Incorrect password" : "User not found");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
        }

        // FIXED: the same message either way.
        body.put("error", "Invalid credentials");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }

    private ResponseEntity<Map<String, Object>> success(User user) {
        String token = jwt.issue(user.getId(), user.getUsername(), user.getRole());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token", token);
        body.put("username", user.getUsername());
        body.put("role", user.getRole());
        body.put("user_id", user.getId());
        return ResponseEntity.ok(body);
    }

    /**
     * Request a password reset.
     *
     * <p><strong>LAB 19 (VULNERABLE):</strong> the token is
     * {@code md5(username + unixTimestamp)}. An attacker who knows only the
     * username and the approximate request time can recompute it offline.
     *
     * <p>The token is also returned in the response body, for lab convenience.
     *
     * <p><strong>FIX:</strong> use {@code secrets.token_urlsafe(32)}, store it
     * with a short expiry, and mark it used after a single redemption. The
     * response should not contain the token at all in production.
     */
    @PostMapping("/reset-request")
    public ResponseEntity<Map<String, Object>> resetRequest(@RequestBody Map<String, String> body) {
        String username = body.get("username");

        String token;
        if (labs.isEnabled("resettoken")) {
            // LAB 19 (VULNERABLE): predictable token.
            //
            // FIX: token = secrets.token_urlsafe(32);
            token = md5.hex(username + (System.currentTimeMillis() / 1000));
        } else {
            // FIXED: cryptographically random, stored, single-use, time-limited.
            token = java.util.UUID.randomUUID().toString()
                    .replace("-", "") + java.util.UUID.randomUUID().toString().replace("-", "");
        }

        PasswordResetToken record = new PasswordResetToken();
        record.setUsername(username);
        record.setToken(token);
        record.setExpiresAt(Instant.now().plus(1, ChronoUnit.HOURS));
        record.setUsed(false);
        resetTokens.save(record);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("message", "If that account exists, a reset link has been sent.");
        // Returned for lab convenience only — remove in production.
        response.put("token", token);
        return ResponseEntity.ok(response);
    }

    /**
     * Redeem a password reset token.
     *
     * <p><strong>LAB 19:</strong> because the token is predictable, an
     * attacker can compute a valid one and take over any account.
     */
    @PostMapping("/reset-confirm")
    public ResponseEntity<Map<String, Object>> resetConfirm(@RequestBody Map<String, String> body) {
        String token = body.get("token");
        String newPassword = body.get("new_password");

        PasswordResetToken record = resetTokens.findByToken(token).orElse(null);
        if (record == null || record.isUsed() || record.getExpiresAt().isBefore(Instant.now())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "Invalid or expired reset token"));
        }

        User user = users.findByUsername(record.getUsername()).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "Invalid or expired reset token"));
        }

        user.setPasswordHash(passwords.hash(newPassword == null ? "" : newPassword));
        users.save(user);
        record.setUsed(true);
        resetTokens.save(record);

        return ResponseEntity.ok(Map.of("message", "Password updated"));
    }
}
