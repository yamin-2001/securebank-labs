package com.securebank.core;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Global exception handling.
 *
 * <p>Two behaviours live here, and they are deliberately kept apart so their
 * fixes stay independent:
 *
 * <ul>
 *   <li><strong>LAB 23 (A10)</strong> — verbose errors. The generic handler
 *       returns the full stack trace, the exception type and the message.
 *       <br><strong>FIX:</strong> return a generic message and log the detail
 *       server-side instead. Also set {@code server.error.include-stacktrace=never}.</li>
 *   <li><strong>LAB 24 (A10)</strong> — type coercion. This lab gets its own
 *       handler for malformed request bodies, so fixing Lab 23 (which changes
 *       the generic handler) does not also fix Lab 24.</li>
 * </ul>
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private final LabToggles labs;

    public ApiExceptionHandler(LabToggles labs) {
        this.labs = labs;
    }

    /**
     * A request for a static resource that does not exist.
     *
     * <p><strong>LAB 6 (FIXED):</strong> with the sensitive files taken off
     * the web root, a request for one of them is simply a missing file. It
     * answers 404 with a short message — no stack trace, no class names.
     *
     * <p>Without this the {@code NoResourceFoundException} falls through to
     * the generic handler below and the client is handed a rendered trace
     * for a request that was nothing more than a 404.
     */
    @ExceptionHandler(org.springframework.web.servlet.resource.NoResourceFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNoResource(
            org.springframework.web.servlet.resource.NoResourceFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", "Not found"));
    }

    /**
     * LAB 23 (VULNERABLE): the generic handler leaks the stack trace,
     * the exception type and the message.
     *
     * <p><strong>FIX:</strong> replace the body with a generic message and log
     * the exception server-side. Never return internals to the client.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleException(Exception ex) {
        if (labs.isEnabled("verboseerror")) {
            StringWriter stack = new StringWriter();
            ex.printStackTrace(new PrintWriter(stack));

            Map<String, Object> body = new LinkedHashMap<>();
            body.put("timestamp", java.time.Instant.now().toString());
            body.put("status", 500);
            body.put("error", "Internal Server Error");
            body.put("exception", ex.getClass().getName());
            body.put("message", ex.getMessage());
            body.put("stackTrace", stack.toString().split("\n"));
            body.put("path", "");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
        }

        // FIXED: a generic message; the detail goes to the server log.
        org.slf4j.LoggerFactory.getLogger(ApiExceptionHandler.class)
                .error("Unhandled exception", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "An internal error occurred"));
    }
}
