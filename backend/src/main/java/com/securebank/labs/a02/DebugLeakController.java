package com.securebank.labs.a02;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <strong>LAB 4 (A02 — Security Misconfiguration): debug mode.</strong>
 *
 * <p><strong>FIXED.</strong> The endpoint used to throw an exception whose
 * message embedded the application's secrets — the JWT signing key and the
 * JDBC connection string, which carries the database username and password —
 * and {@code server.error.include-*} was set to {@code always}, so the
 * response body carried the full stack trace and every one of those values.
 *
 * <p>Know the signing key and you can forge tokens for any user. Read the
 * JDBC URL and you have the database credentials.
 *
 * <p>The endpoint now returns a plain 404 with no secret in it, and
 * {@code server.error.include-*} is set to {@code never} in
 * {@code application.yml} so the framework's own error pages stop leaking
 * internals too. A debug endpoint in production should not exist at all.
 */
@RestController
@RequestMapping("/api/debug")
public class DebugLeakController {

    /**
     * Trigger the failure.
     *
     * <p><strong>LAB 4 (FIXED):</strong> the message carries no secret, and
     * the global error settings no longer render a stack trace to the client.
     *
     * @param detail free-text detail appended to the failure message
     */
    @GetMapping("/boom")
    public ResponseEntity<Map<String, Object>> boom(
            @org.springframework.web.bind.annotation.RequestParam(
                    name = "detail", required = false, defaultValue = "diagnostic") String detail) {

        // FIXED: a plain message, and the error handler returns a generic body.
        // The detail is not echoed back either — a diagnostic endpoint has no
        // business reflecting caller-supplied text into an error page.
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "debug endpoint is disabled");
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(body);
    }
}
