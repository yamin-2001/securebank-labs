package com.securebank.labs.a02;

import java.util.LinkedHashMap;
import java.util.Map;

import com.securebank.core.LabToggles;
import com.securebank.security.JwtKeys;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <strong>LAB 4 (A02 — Security Misconfiguration): debug mode.</strong>
 *
 * <p>The debug endpoint throws an exception whose message embeds the
 * application's secrets: the JWT signing key and the JDBC connection string
 * (which carries the database username and password). Combined with
 * {@code server.error.include-*} set to {@code always} in
 * {@code application.yml}, the response body contains the full stack trace
 * and every one of those values.
 *
 * <p>Know the {@code SECRET_KEY} and you can forge tokens and session
 * cookies for any user. Read the JDBC URL and you have the database
 * credentials.
 *
 * <p><strong>FIX:</strong> two things, and you need both.
 * <ol>
 *   <li>Set {@code server.error.include-stacktrace=never},
 *       {@code .include-message=never}, {@code .include-exception=never} and
 *       {@code .include-binding-errors=never} in {@code application.yml}.</li>
 *   <li>Stop putting secrets in the exception message — see
 *       {@link #boom(String)} below. A debug endpoint in production should
 *       not exist at all; delete it.</li>
 * </ol>
 */
@RestController
@RequestMapping("/api/debug")
public class DebugLeakController {

    private final LabToggles labs;

    public DebugLeakController(LabToggles labs) {
        this.labs = labs;
    }

    /**
     * Trigger the failure.
     *
     * @param detail free-text detail appended to the failure message
     */
    @GetMapping("/boom")
    public ResponseEntity<Map<String, Object>> boom(
            @org.springframework.web.bind.annotation.RequestParam(
                    name = "detail", required = false, defaultValue = "diagnostic") String detail) {

        if (labs.isEnabled("debugtrace")) {
            // LAB 4 (VULNERABLE): the exception message carries the secrets.
            //
            // FIX: throw a plain exception with no secret in the message, and
            // turn off server.error.include-* in application.yml.
            throw new IllegalStateException(
                    "diagnostic failure while loading profile [" + detail + "]"
                            + " -- jwt signing secret=" + JwtKeys.SECRET
                            + " jdbc url=jdbc:postgresql://localhost:5432/securebank"
                            + " db user=securebank db password=securebank");
        }

        // FIXED: a plain message, and the error handler returns a generic body.
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "debug endpoint is disabled");
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(body);
    }
}
