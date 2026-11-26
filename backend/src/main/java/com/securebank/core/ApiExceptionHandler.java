package com.securebank.core;

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
 *   <li><strong>LAB 23 (A10) — FIXED.</strong> The generic handler used to
 *       return the full stack trace, the exception type and the message to
 *       the client. It now returns a generic message and logs the detail
 *       server-side. The {@code server.error.include-*} settings are set to
 *       {@code never} as well, so the framework's own error page does not
 *       render internals either.</li>
 *   <li><strong>LAB 24 (A10)</strong> — type coercion. This lab gets its own
 *       handler for malformed request bodies, so the two A10 fixes stay
 *       independent of one another.</li>
 * </ul>
 */
@RestControllerAdvice
public class ApiExceptionHandler {

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
     * LAB 23 (FIXED): the generic handler returns a generic message; the
     * detail goes to the server log and never to the client.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleException(Exception ex) {
        org.slf4j.LoggerFactory.getLogger(ApiExceptionHandler.class)
                .error("Unhandled exception", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "An internal error occurred"));
    }
}
