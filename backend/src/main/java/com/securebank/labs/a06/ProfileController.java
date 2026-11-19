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
 *
 * <p><strong>FIXED.</strong> The intended end state binds only the fields a
 * customer is allowed to change — never {@code role}, never {@code id},
 * never {@code passwordHash} — and leaves role changes to a separate,
 * privileged endpoint.
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
     * <p><strong>LAB 15 (FIXED):</strong> only the fields a customer owns
     * are applied. {@code role}, {@code id}, {@code username} and
     * {@code password_hash} are never read from the request body — a role
     * change is a privileged operation and belongs on a separate, admin-only
     * endpoint.
     */
    @PatchMapping
    public ResponseEntity<Map<String, Object>> update(@RequestBody Map<String, Object> body) {
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
