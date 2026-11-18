package com.securebank.labs.a02;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.securebank.core.LabToggles;
import com.securebank.core.PasswordHasher;
import com.securebank.domain.User;
import com.securebank.domain.repo.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <strong>LAB 5 (A02 — Security Misconfiguration): default admin credentials.</strong>
 *
 * <p>The operations console at {@code /admin-panel/**} ships with the
 * username and password {@code admin / admin}. Logging in with them gives
 * full read/write access to every user, account and transfer, without
 * touching the API at all.
 *
 * <p>Note the URL space: {@code /admin-panel/**} is deliberately distinct from
 * {@code /api/admin/**}. Lab 2 (the missing role check) lives on the API
 * side; Lab 5 lives here. They must be fixable independently.
 *
 * <p><strong>FIX:</strong> stop accepting the default password.
 * <ul>
 *   <li>Seed a strong, unique admin password (or none at all — force a
 *       password reset on first boot).</li>
 *   <li>Store it with a proper adaptive hash (BCrypt/Argon2) instead of MD5.</li>
 *   <li>Restrict {@code /admin-panel/**} to an internal network or an IP
 *       allowlist, and turn the panel off in production.</li>
 * </ul>
 */
@RestController
@RequestMapping("/admin-panel")
public class AdminPanelController {

    /** The credentials the panel was shipped with. */
    public static final String DEFAULT_USERNAME = "admin";
    public static final String DEFAULT_PASSWORD = "admin";

    private final UserRepository users;
    private final LabToggles labs;
    private final PasswordHasher passwords;

    public AdminPanelController(UserRepository users, LabToggles labs, PasswordHasher passwords) {
        this.users = users;
        this.labs = labs;
        this.passwords = passwords;
    }

    /**
     * The panel's own login endpoint.
     *
     * <p><strong>LAB 5 (VULNERABLE):</strong> accepts {@code admin / admin}.
     *
     * <p><strong>FIX — two halves, you need both:</strong>
     * <ol>
     *   <li>Rotate the admin's password. The seeded hash in
     *       {@code data.sql} is {@code md5("admin")}, so as long as that row
     *       is unchanged, {@code admin / admin} still matches. Change the
     *       stored hash (ideally to a BCrypt hash, per Lab 7).</li>
     *   <li>Stop comparing against a hardcoded literal. The intended end
     *       state is {@link #loginFixed(String, String)} — it looks the user
     *       up by username and compares the submitted password against the
     *       stored hash, so there is no default credential left in the code
     *       to find.</li>
     * </ol>
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

        if (labs.isEnabled("admincreds")) {
            // LAB 5 (VULNERABLE): the shipped default credentials always work.
            //
            // FIX: delete this branch and call loginFixed(username, password),
            // AND rotate the admin's stored password hash in data.sql.
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
        }

        // ---- FIX (the intended final state) ----
        return loginFixed(username, password);
    }

    /**
     * ---- FIX (the intended final state) ----
     *
     * <p>Authenticate against the stored credential instead of a hardcoded
     * literal. Once the admin's password is changed in the database, the
     * default stops working.
     */
    private ResponseEntity<Map<String, Object>> loginFixed(String username, String password) {
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

    /** The console's main screen: every user in the system. */
    @GetMapping("/users")
    public List<Map<String, Object>> panelUsers() {
        return users.findAll().stream().map(u -> {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("id", u.getId());
            body.put("username", u.getUsername());
            body.put("email", u.getEmail());
            body.put("role", u.getRole());
            body.put("password_hash", u.getPasswordHash());
            return body;
        }).toList();
    }
}
