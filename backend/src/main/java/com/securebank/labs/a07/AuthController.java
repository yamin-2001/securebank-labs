package com.securebank.labs.a07;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;

import com.securebank.core.PasswordHasher;
import com.securebank.domain.PasswordResetToken;
import com.securebank.domain.User;
import com.securebank.domain.repo.PasswordResetTokenRepository;
import com.securebank.domain.repo.UserRepository;
import com.securebank.security.LabJwtService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Authentication endpoints.
 *
 * <p>Home to four labs, each with its own fix location and its own toggle:
 * <ul>
 *   <li><strong>LAB 10 (FIXED)</strong> (A05) — SQL injection / login bypass</li>
 *   <li><strong>LAB 16 (FIXED)</strong> (A06) — account enumeration via error messages</li>
 *   <li><strong>LAB 17 (FIXED)</strong> (A07) — no rate limiting</li>
 *   <li><strong>LAB 19 (FIXED)</strong> (A07) — predictable password reset token</li>
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
    private final PasswordHasher passwords;
    private final LabJwtService jwt;
    private final LoginAttemptService attempts;

    public AuthController(UserRepository users, PasswordResetTokenRepository resetTokens,
                          PasswordHasher passwords,
                          LabJwtService jwt,
                          LoginAttemptService attempts) {
        this.users = users;
        this.resetTokens = resetTokens;
        this.passwords = passwords;
        this.jwt = jwt;
        this.attempts = attempts;
    }

    /**
     * Log in and receive a bearer token.
     *
     * <p><strong>LAB 10 (FIXED):</strong> the lookup is parameterized — the
     * username is bound as a JDBC parameter, so a payload like
     * {@code admin' --} is matched as a literal username instead of
     * commenting out the rest of the WHERE clause.
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

        // LAB 17 (FIXED): the account has to be within its attempt budget
        // before we even look at the password. A brute-force loop now hits
        // a 429 after MAX_ATTEMPTS failures.
        attempts.applyRateLimit(username);

        // FIXED: a parameterised lookup — the payload is treated as data.
        User user = users.findByUsername(username).orElse(null);
        if (user == null || !passwords.matches(password == null ? "" : password, user.getPasswordHash())) {
            return failure(username);
        }
        return success(user);
    }

    /**
     * A failed login.
     *
     * <p><strong>LAB 16 (FIXED):</strong> the response is the same whether
     * the username exists or the password was wrong. The old code returned
     * "User not found" versus "Incorrect password", which told an attacker
     * which usernames are real.
     */
    private ResponseEntity<Map<String, Object>> failure(String username) {
        // LAB 17: a failed attempt counts towards the account's budget.
        attempts.recordFailure(username);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "Invalid credentials");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }

    /**
     * LAB 17 (FIX helper): the response returned once an account has spent
     * its attempt budget.
     *
     * <p>FIX: return this from the login endpoint when
     * {@code attempts.isBlocked(username)} is true.
     */
    private ResponseEntity<Map<String, Object>> tooManyAttempts() {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(Map.of("error", "Too many failed login attempts. Try again later."));
    }

    /**
     * LAB 17: the account has spent its attempt budget.
     *
     * <p>On the vulnerable build this exception is never thrown — the
     * vulnerable {@code applyRateLimit} neither counts nor refuses. Once the
     * fix is in place, the service throws it and this handler turns it into
     * a 429.
     */
    @ExceptionHandler(LoginAttemptService.TooManyAttemptsException.class)
    public ResponseEntity<Map<String, Object>> tooManyAttemptsException(
            LoginAttemptService.TooManyAttemptsException e) {
        return tooManyAttempts();
    }

    private ResponseEntity<Map<String, Object>> success(User user) {
        // LAB 17: a successful login clears the account's counter.
        attempts.recordSuccess(user.getUsername());

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
     * <p><strong>LAB 19 (FIXED):</strong> the token used to be
     * {@code md5(username + unixTimestamp)}. An attacker who knew only the
     * username and the approximate request time could recompute it offline.
     *
     * <p>The token is now cryptographically random, stored with a short
     * expiry, and marked used after a single redemption. It is returned in
     * the response body for lab convenience; in production it would only be
     * emailed.
     */
    @PostMapping("/reset-request")
    public ResponseEntity<Map<String, Object>> resetRequest(@RequestBody Map<String, String> body) {
        String username = body.get("username");

        // 32 bytes from a CSPRNG — not derived from anything the attacker
        // can know or guess.
        byte[] random = new byte[32];
        new java.security.SecureRandom().nextBytes(random);
        String token = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(random);

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
