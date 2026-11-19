package com.securebank.labs.a02;

import java.util.LinkedHashMap;
import java.util.Map;

import com.securebank.security.JwtKeys;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

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
 */
@RestController
@RequestMapping("/api/debug")
public class DebugLeakController {

    /**
     * Trigger the failure.
     *
     * @param detail free-text detail appended to the failure message
     */
    @GetMapping("/boom")
    public ResponseEntity<Map<String, Object>> boom(
            @org.springframework.web.bind.annotation.RequestParam(
                    name = "detail", required = false, defaultValue = "diagnostic") String detail) {

        // The exception message carries the secrets.
        throw new IllegalStateException(
                "diagnostic failure while loading profile [" + detail + "]"
                        + " -- jwt signing secret=" + JwtKeys.HARDCODED_SECRET
                        + " jdbc url=jdbc:postgresql://localhost:5432/securebank"
                        + " db user=securebank db password=securebank");
    }
}
