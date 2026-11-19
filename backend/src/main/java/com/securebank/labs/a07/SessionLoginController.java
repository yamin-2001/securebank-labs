package com.securebank.labs.a07;

import java.util.LinkedHashMap;
import java.util.Map;

import com.securebank.domain.User;
import com.securebank.domain.repo.UserRepository;
import com.securebank.core.PasswordHasher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <strong>LAB 18 (A07 — Identification and Authentication Failures): session
 * fixation.</strong>
 *
 * <p>This endpoint authenticates against an HTTP session rather than
 * returning a bearer token, so that the session id can be observed before
 * and after login.
 *
 * <p>The session id is <em>not</em> rotated on successful authentication.
 * An attacker who can set a cookie in the victim's browser — through the
 * stored XSS in Lab 13, for instance — can then wait for the victim to log
 * in and reuse the same session id to ride their authenticated session.
 *
 * <p>Spring Security's default session-fixation protection would rotate the
 * id for us. It is switched off in {@code SecurityConfig.sessionChain()}
 * with {@code sessionFixation(fixation -> fixation.none())}, precisely so
 * that this lab is reachable.
 */
@RestController
@RequestMapping("/api")
public class SessionLoginController {

    private final UserRepository users;
    private final PasswordHasher passwords;

    public SessionLoginController(UserRepository users, PasswordHasher passwords) {
        this.users = users;
        this.passwords = passwords;
    }

    /**
     * Log in, establishing a session.
     *
     * <p><strong>LAB 18 (VULNERABLE):</strong> the session id survives
     * authentication unchanged.
     */
    @PostMapping("/auth/login-session")
    public ResponseEntity<Map<String, Object>> loginSession(@RequestBody Map<String, String> body,
                                                            HttpServletRequest request) {
        String username = body.get("username");
        String password = body.get("password");

        User user = users.findByUsername(username).orElse(null);
        if (user == null || !passwords.matches(password == null ? "" : password, user.getPasswordHash())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid credentials"));
        }

        HttpSession session = request.getSession(true);

        // The id the client arrived with, before any rotation. On the
        // vulnerable build this is the id the client will still hold after
        // the response — that is the whole attack.
        String incomingId = session.getId();

        session.setAttribute("user_id", user.getId());
        session.setAttribute("username", user.getUsername());
        session.setAttribute("role", user.getRole());

        // LAB 18 (VULNERABLE): the session id is NOT rotated. The id the
        // attacker planted before the victim logged in is now an
        // authenticated session.

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("message", "Logged in");
        out.put("session_id", session.getId());
        // The id the client presented before the login, so the harness can
        // tell whether it was rotated.
        out.put("previous_session_id", incomingId);
        out.put("username", user.getUsername());
        out.put("role", user.getRole());
        return ResponseEntity.ok(out);
    }

    /**
     * Establish a session before logging in.
     *
     * <p>This is the "attacker visits the site" step of the fixation attack:
     * it hands out a session id that the attacker then plants in the victim's
     * browser. The id is valid — it is a real server-side session — it just
     * has no attributes yet.
     */
    @GetMapping("/session/start")
    public ResponseEntity<Map<String, Object>> start(HttpServletRequest request) {
        HttpSession session = request.getSession(true);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("session_id", session.getId());
        out.put("message", "Session started. Log in to authenticate it.");
        return ResponseEntity.ok(out);
    }

    /**
     * Who the current session belongs to.
     */
    @GetMapping("/session/whoami")
    public ResponseEntity<Map<String, Object>> whoami(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("user_id") == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Not logged in"));
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("session_id", session.getId());
        out.put("user_id", session.getAttribute("user_id"));
        out.put("username", session.getAttribute("username"));
        out.put("role", session.getAttribute("role"));
        return ResponseEntity.ok(out);
    }
}
