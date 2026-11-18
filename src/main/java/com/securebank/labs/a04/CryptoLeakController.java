package com.securebank.labs.a04;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.securebank.core.AuthContext;
import com.securebank.core.LabToggles;
import com.securebank.core.PasswordHasher;
import com.securebank.domain.User;
import com.securebank.domain.repo.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Cryptography-related endpoints. Home of two A04 labs:
 *
 * <ul>
 *   <li><strong>LAB 7</strong> — unsalted MD5 password hashes.</li>
 *   <li><strong>LAB 9</strong> — PII in cleartext responses and in logs.</li>
 * </ul>
 *
 * <p>Each lives in its own method so fixing one does not touch the other.
 */
@RestController
@RequestMapping("/api/crypto")
public class CryptoLeakController {

    private static final Logger log = LoggerFactory.getLogger(CryptoLeakController.class);

    private final UserRepository users;
    private final LabToggles labs;
    private final PasswordHasher passwords;

    public CryptoLeakController(UserRepository users, LabToggles labs, PasswordHasher passwords) {
        this.users = users;
        this.labs = labs;
        this.passwords = passwords;
    }

    /**
     * <strong>LAB 7 (VULNERABLE):</strong> every user's password hash, in the
     * clear, with no salt.
     *
     * <p>Unsalted MD5 is not password hashing — it is a rainbow table
     * lookup. Every hash below is in the public CrackStation database.
     *
     * <p><strong>FIX:</strong> replace the storage scheme, not just this
     * endpoint. Store BCrypt/Argon2 hashes with a per-user salt, re-seed or
     * migrate the existing rows, and never hand hashes to a client at all —
     * an admin view should show a hash <em>prefix</em> at most.
     *
     * <p>Note: fixing this does <strong>not</strong> fix Lab 10. The SQL
     * comment in the login-bypass payload removes the password predicate
     * entirely, so the injection still works whatever the hashing algorithm.
     */
    @GetMapping("/hashes")
    public List<Map<String, Object>> hashes() {
        List<Map<String, Object>> out = new java.util.ArrayList<>();
        for (User user : users.findAll()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", user.getId());
            row.put("username", user.getUsername());
            row.put("algorithm", passwords.isLegacyHash(user.getPasswordHash())
                    ? "MD5" : "PBKDF2-HMAC-SHA256");
            row.put("password_hash", user.getPasswordHash());
            row.put("salt", passwords.isLegacyHash(user.getPasswordHash())
                    ? null : "<per-user salt>");
            out.add(row);
        }
        return out;
    }

    /**
     * <strong>LAB 9 (VULNERABLE):</strong> the caller's full profile — full
     * name, email, unmasked account number, sort code and balance — returned
     * in plaintext and written to the application log.
     *
     * <p><strong>FIX:</strong> mask the sensitive fields
     * ({@code ACC-****1001}, {@code 20-**-**}) and never log PII. Log the
     * user id, not the profile.
     */
    @GetMapping("/profile")
    public Map<String, Object> profile() {
        Long userId = AuthContext.userId().orElse(0L);
        User user = users.findById(userId).orElse(null);
        if (user == null) {
            return Map.of("error", "no profile");
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("user_id", user.getId());
        body.put("username", user.getUsername());
        body.put("full_name", user.getFullName());
        body.put("email", user.getEmail());
        body.put("account_number", "ACC-1001");
        body.put("sort_code", "20-00-00");
        body.put("balance", 4200.00);
        body.put("currency", "GBP");

        if (labs.isEnabled("pii")) {
            // LAB 9 (VULNERABLE): the unmasked profile is written to stdout,
            // where it will sit in the log files for years.
            //
            // FIX: delete this log line, and mask the fields above.
            log.info("profile lookup for user {}: name={} email={} account={} "
                            + "sort_code={} balance={}",
                    user.getId(), user.getFullName(), user.getEmail(),
                    "ACC-1001", "20-00-00", 4200.00);
            return body;
        }

        // ---- FIX (the intended final state) ----
        body.put("full_name", maskName(user.getFullName()));
        body.put("email", maskEmail(user.getEmail()));
        body.put("account_number", "ACC-****1001");
        body.put("sort_code", "20-**-**");
        body.remove("balance");
        log.info("profile lookup for user id {}", user.getId());
        return body;
    }

    private String maskName(String name) {
        if (name == null || name.isBlank()) {
            return null;
        }
        String[] parts = name.split(" ");
        StringBuilder sb = new StringBuilder();
        for (String part : parts) {
            if (sb.length() > 0) {
                sb.append(' ');
            }
            sb.append(part.charAt(0)).append("***");
        }
        return sb.toString();
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return null;
        }
        int at = email.indexOf('@');
        String local = email.substring(0, at);
        String domain = email.substring(at);
        String head = local.isEmpty() ? "" : local.substring(0, 1);
        return head + "***" + domain;
    }
}
