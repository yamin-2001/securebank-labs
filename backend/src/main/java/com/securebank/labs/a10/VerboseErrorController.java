package com.securebank.labs.a10;

import java.util.LinkedHashMap;
import java.util.Map;

import com.securebank.core.LabToggles;
import org.springframework.http.HttpStatus;
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
 * <p><strong>FIX:</strong> validate the input at the boundary and return a
 * clean 400 with a message that says what was wrong and nothing more. Set
 * {@code server.error.include-stacktrace=never} (and its siblings) so the
 * framework's own error pages stop leaking internals too.
 *
 * <p>Lab 24 (type coercion) lives in its own controller and has its own
 * exception handler, so fixing this one does not fix that one.
 */
@RestController
@RequestMapping("/api/transfers")
public class VerboseErrorController {

    private final LabToggles labs;

    public VerboseErrorController(LabToggles labs) {
        this.labs = labs;
    }

    /**
     * An account summary for one id.
     *
     * <p><strong>LAB 23 (VULNERABLE):</strong> the id is parsed with
     * {@code Integer.parseInt} and the {@link NumberFormatException} is
     * allowed to escape, so the client gets the full stack trace.
     *
     * <p><strong>FIX:</strong> delete the vulnerable branch and use
     * {@link #summaryFixed(String)}.
     */
    @GetMapping("/account-summary")
    public ResponseEntity<Map<String, Object>> summary(@RequestParam("id") String id) {
        if (labs.isEnabled("verboseerror")) {
            // LAB 23 (VULNERABLE): parseInt throws, and the global handler
            // renders the stack trace back to the client.
            //
            // FIX: use summaryFixed(...) below.
            int accountId = Integer.parseInt(id);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("account_id", accountId);
            out.put("currency", "GBP");
            return ResponseEntity.ok(out);
        }

        // ---- FIX (the intended final state) ----
        return summaryFixed(id);
    }

    /**
     * ---- FIX (the intended final state) -------------------------------
     *
     * <p>The input is validated at the boundary. A bad id is a client
     * error, so it gets a 400 with a short message — no exception type, no
     * stack trace, no internals.
     */
    private ResponseEntity<Map<String, Object>> summaryFixed(String id) {
        int accountId;
        try {
            accountId = Integer.parseInt(id);
        } catch (NumberFormatException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "The account id must be a number"));
        }
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
        if (labs.isEnabled("verboseerror") && raw instanceof String) {
            // LAB 23 (VULNERABLE): the same unhandled parse, this time from
            // a request body.
            //
            // FIX: validate before parsing.
            int accountId = Integer.parseInt(String.valueOf(raw));
            return ResponseEntity.ok(Map.of("account_id", accountId, "currency", "GBP"));
        }
        try {
            int accountId = Integer.parseInt(String.valueOf(raw));
            return ResponseEntity.ok(Map.of("account_id", accountId, "currency", "GBP"));
        } catch (NumberFormatException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "The account id must be a number"));
        }
    }
}
