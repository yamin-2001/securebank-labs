package com.securebank.labs.a04;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.securebank.core.AuthContext;
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
 *   <li><strong>LAB 7 (FIXED)</strong> — passwords are stored as salted
 *       PBKDF2-HMAC-SHA256, not unsalted MD5.</li>
 *   <li><strong>LAB 9 (FIXED)</strong> — PII is masked in the response and
 *       never written to the log.</li>
 * </ul>
 *
 * <p>Each lives in its own method so fixing one does not touch the other.
 */
@RestController
@RequestMapping("/api/crypto")
public class CryptoLeakController {

    private static final Logger log = LoggerFactory.getLogger(CryptoLeakController.class);

    private final UserRepository users;
    private final PasswordHasher passwords;

    public CryptoLeakController(UserRepository users, PasswordHasher passwords) {
        this.users = users;
        this.passwords = passwords;
    }

    /**
     * <strong>LAB 7 (FIXED):</strong> every user's password hash, in the
     * clear.
     *
     * <p>The hashes are salted PBKDF2-HMAC-SHA256 now, so they are not a
     * rainbow table lookup any more. They should still not be handed to a
     * client at all — an admin view should show a hash <em>prefix</em> at
     * most, and no endpoint should expose a credential.
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
     * <strong>LAB 9 (FIXED):</strong> the sensitive fields are masked
     * ({@code ACC-****1001}, {@code 20-**-**}), the balance is not returned
     * at all, and nothing containing PII is written to the log. The log line
     * carries the user id and nothing else.
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
        body.put("full_name", maskName(user.getFullName()));
        body.put("email", maskEmail(user.getEmail()));
        body.put("account_number", "ACC-****1001");
        body.put("sort_code", "20-**-**");
        body.put("currency", "GBP");

        // Log the user id, not the profile. The name, email, account number
        // and balance must never reach the log files.
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
