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
 * <p><strong>FIXED.</strong> The session id used to survive authentication
 * unchanged. An attacker who could set a cookie in the victim's browser —
 * through the stored XSS in Lab 13, for instance — could then wait for the
 * victim to log in and reuse the same session id to ride their
 * authenticated session.
 *
 * <p>The id is now rotated at the moment of authentication, so any id the
 * attacker planted beforehand is worthless afterwards.
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
     * <p><strong>LAB 18 (FIXED):</strong> the session id is rotated at the
     * moment of authentication, so any id the attacker planted before the
     * login is worthless afterwards.
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

        // LAB 18 (FIXED): rotate the id now that the session carries the
        // authenticated attributes. The rotation carries them across to the
        // new session, so the caller stays logged in.
        session = rotateSessionId(request, session);

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
     * ---- FIX (the intended final state) ----
     *
     * <p>Rotating the session id at the moment of authentication means any
     * id the attacker planted before the login is worthless afterwards.
     *
     * <p>The old session is invalidated and a brand-new one is created, with
     * the authenticated attributes carried across. That is the pattern
     * Flask's {@code session.regenerate()} implements, and it is the one
     * that works everywhere — {@code request.changeSessionId()} is a
     * container-specific convenience that some setups silently ignore.
     */
    private HttpSession rotateSessionId(HttpServletRequest request, HttpSession session) {
        Object userId = session.getAttribute("user_id");
        Object username = session.getAttribute("username");
        Object role = session.getAttribute("role");

        session.invalidate();

        HttpSession fresh = request.getSession(true);
        fresh.setAttribute("user_id", userId);
        fresh.setAttribute("username", username);
        fresh.setAttribute("role", role);
        return fresh;
    }

    /**
     * Establish a session before logging in.
     *
     * <p>This is the "attacker visits the site" step of the fixation attack:
     * it hands out a session id that the attacker then plants in the victim's
     * browser. The id is valid — it is a real server-side session — it just
     * has no attributes yet.
     *
     * <p>FIX: nothing needs to change here. The bug is that
     * {@link #loginSession(Map, HttpServletRequest)} does not rotate this id.
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
