package com.securebank.labs.a02;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
 * <p><strong>FIXED.</strong> The operations console at
 * {@code /admin-panel/**} used to ship with the username and password
 * {@code admin / admin}. Logging in with them gave full read/write access to
 * every user, account and transfer, without touching the API at all.
 *
 * <p>There is no default credential in the code any more: the panel
 * authenticates against the stored hash, and the admin's hash has been
 * rotated in {@code data.sql}.
 *
 * <p>Note the URL space: {@code /admin-panel/**} is deliberately distinct from
 * {@code /api/admin/**}. Lab 2 (the missing role check) lives on the API
 * side; Lab 5 lives here. They must be fixable independently.
 *
 * <p>Still worth doing in a real deployment: restrict
 * {@code /admin-panel/**} to an internal network or an IP allowlist, and
 * turn the panel off in production entirely.
 */
@RestController
@RequestMapping("/admin-panel")
public class AdminPanelController {

    private final UserRepository users;
    private final PasswordHasher passwords;

    public AdminPanelController(UserRepository users, PasswordHasher passwords) {
        this.users = users;
        this.passwords = passwords;
    }

    /**
     * The panel's own login endpoint.
     *
     * <p><strong>LAB 5 (FIXED):</strong> there is no default credential left
     * in the code to find. The panel looks the user up by username and
     * compares the submitted password against the stored hash, and the
     * admin's stored hash has been rotated in {@code data.sql} — so
     * {@code admin / admin} no longer authenticates.
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

        return loginFixed(username, password);
    }

    /**
     * Authenticate against the stored credential instead of a hardcoded
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
