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
 * <p>The operations console at {@code /admin-panel/**} ships with the
 * username and password {@code admin / admin}. Logging in with them gives
 * full read/write access to every user, account and transfer, without
 * touching the API at all.
 *
 * <p>Note the URL space: {@code /admin-panel/**} is deliberately distinct from
 * {@code /api/admin/**}. Lab 2 (the missing role check) lives on the API
 * side; Lab 5 lives here. They must be fixable independently.
 */
@RestController
@RequestMapping("/admin-panel")
public class AdminPanelController {

    /** The credentials the panel was shipped with. */
    public static final String DEFAULT_USERNAME = "admin";
    public static final String DEFAULT_PASSWORD = "admin";

    private final UserRepository users;
    private final PasswordHasher passwords;

    public AdminPanelController(UserRepository users, PasswordHasher passwords) {
        this.users = users;
        this.passwords = passwords;
    }

    /**
     * The panel's own login endpoint.
     *
     * <p><strong>LAB 5 (VULNERABLE):</strong> accepts {@code admin / admin}.
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

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
