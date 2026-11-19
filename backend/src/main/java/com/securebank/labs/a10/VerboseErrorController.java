package com.securebank.labs.a10;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * <strong>LAB 23 (A10 — Mishandling of Exceptional Conditions): verbose
 * errors.</strong>
 *
 * <p>An unparseable path parameter is turned into a raw exception and allowed
 * to propagate. The global handler in {@code core/ApiExceptionHandler}
 * renders the stack trace, the exception type and the message back to the
 * client — so the attacker learns the framework version, the class names of
 * the application's internals and the shape of the server's code.
 *
 * <p>Lab 24 (type coercion) lives in its own controller and has its own
 * exception handler, so fixing this one does not fix that one.
 */
@RestController
@RequestMapping("/api/transfers")
public class VerboseErrorController {

    public VerboseErrorController() {
    }

    /**
     * An account summary for one id.
     *
     * <p><strong>LAB 23 (VULNERABLE):</strong> the id is parsed with
     * {@code Integer.parseInt} and the {@link NumberFormatException} is
     * allowed to escape, so the client gets the full stack trace.
     */
    @GetMapping("/account-summary")
    public ResponseEntity<Map<String, Object>> summary(@RequestParam("id") String id) {
        int accountId = Integer.parseInt(id);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("account_id", accountId);
        out.put("currency", "GBP");
        return ResponseEntity.ok(out);
    }

    /**
     * A second route into the same flaw, for the report view.
     *
     * <p>Kept separate so the lab panel can point at two call sites and the
     * learner sees that the fix has to cover both.
     */
    @PostMapping("/account-summary")
    public ResponseEntity<Map<String, Object>> summaryPost(@RequestBody Map<String, Object> body) {
        Object raw = body.get("id");
        int accountId = Integer.parseInt(String.valueOf(raw));
        return ResponseEntity.ok(Map.of("account_id", accountId, "currency", "GBP"));
    }
}
