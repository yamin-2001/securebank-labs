package com.securebank.labs.a06;

import java.util.LinkedHashMap;
import java.util.Map;

import com.securebank.core.AuthContext;
import com.securebank.domain.User;
import com.securebank.domain.repo.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <strong>LAB 15 (A06 — Insecure Design): mass assignment / self-promotion.</strong>
 *
 * <p>The profile endpoint binds the request body straight onto the
 * {@link User} entity. Because the entity carries a {@code role} column,
 * a customer can send {@code {"role": "admin"}} and become an admin.
 *
 * <p>Mass assignment is an insecure-design flaw rather than a parsing bug:
 * the request DTO and the persistence entity are the same shape, so every
 * writable column is an implicit part of the public API.
 */
@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    private final UserRepository users;

    public ProfileController(UserRepository users) {
        this.users = users;
    }

    /** The caller's own profile. */
    @GetMapping
    public ResponseEntity<Map<String, Object>> profile() {
        Long callerId = AuthContext.userId().orElse(null);
        User user = users.findById(callerId).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "No such user"));
        }
        return ResponseEntity.ok(view(user));
    }

    /**
     * Update the caller's profile.
     *
     * <p><strong>LAB 15 (VULNERABLE):</strong> the whole request body is
     * bound onto the entity, so {@code role} is writable.
     */
    @PatchMapping
    public ResponseEntity<Map<String, Object>> update(@RequestBody Map<String, Object> body) {
        Long callerId = AuthContext.userId().orElse(null);
        User user = users.findById(callerId).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "No such user"));
        }
        applyAllFields(user, body);
        users.save(user);
        return ResponseEntity.ok(view(user));
    }

    /**
     * LAB 15 (VULNERABLE): apply every field in the body to the entity.
     */
    private void applyAllFields(User user, Map<String, Object> body) {
        if (body.containsKey("username")) {
            user.setUsername(String.valueOf(body.get("username")));
        }
        if (body.containsKey("password_hash")) {
            user.setPasswordHash(String.valueOf(body.get("password_hash")));
        }
        if (body.containsKey("email")) {
            user.setEmail(String.valueOf(body.get("email")));
        }
        if (body.containsKey("full_name")) {
            user.setFullName(String.valueOf(body.get("full_name")));
        }
        if (body.containsKey("role")) {
            user.setRole(String.valueOf(body.get("role")));
        }
    }

    private static Map<String, Object> view(User user) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", user.getId());
        body.put("username", user.getUsername());
        body.put("email", user.getEmail());
        body.put("full_name", user.getFullName());
        body.put("role", user.getRole());
        return body;
    }
}
