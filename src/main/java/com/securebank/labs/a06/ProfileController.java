package com.securebank.labs.a06;

import java.util.LinkedHashMap;
import java.util.Map;

import com.securebank.core.AuthContext;
import com.securebank.core.LabToggles;
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
 * <p><strong>FIX:</strong> delete the vulnerable branch. The intended end
 * state binds only the fields a customer is allowed to change — never
 * {@code role}, never {@code id}, never {@code passwordHash} — and leaves
 * role changes to a separate, privileged endpoint.
 */
@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    private final UserRepository users;
    private final LabToggles labs;

    public ProfileController(UserRepository users, LabToggles labs) {
        this.users = users;
        this.labs = labs;
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
     *
     * <p><strong>FIX:</strong> delete this branch and use
     * {@link #updateFixed(Map)}.
     */
    @PatchMapping
    public ResponseEntity<Map<String, Object>> update(@RequestBody Map<String, Object> body) {
        if (labs.isEnabled("massassign")) {
            // LAB 15 (VULNERABLE): the body is bound onto the entity
            // wholesale. `{"role": "admin"}` promotes the caller.
            //
            // FIX: use updateFixed(body) below.
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

        // ---- FIX (the intended final state) ----
        return updateFixed(body);
    }

    /**
     * ---- FIX (the intended final state) ----
     *
     * <p>Only the fields a customer owns are applied. {@code role},
     * {@code id}, {@code username} and {@code password_hash} are never read
     * from the request body — a role change is a privileged operation and
     * belongs on a separate, admin-only endpoint.
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
    }

    /**
     * LAB 15 (VULNERABLE): apply every field in the body to the entity.
     *
     * <p>FIX: delete this method — {@link #updateFixed(Map)} replaces it.
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
