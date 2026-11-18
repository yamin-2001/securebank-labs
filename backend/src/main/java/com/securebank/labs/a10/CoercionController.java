package com.securebank.labs.a10;

import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.Map;

import com.securebank.core.LabToggles;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <strong>LAB 24 (A10 — Mishandling of Exceptional Conditions): type
 * coercion leaks the object model.</strong>
 *
 * <p>This endpoint takes a strictly-typed request body. When the client
 * sends {@code "amount": "notanumber"}, Jackson cannot turn the string into
 * a {@link BigDecimal} and throws a message-coercion exception. That
 * exception's text names the Java type it wanted, the field it was reading,
 * and the path through the application's own classes.
 *
 * <p>Lab 24 gets its <strong>own</strong> {@code @ExceptionHandler} — not
 * the global one in {@code core/ApiExceptionHandler}. That is deliberate:
 * Lab 23's fix changes the global handler, and if Lab 24 shared it the two
 * labs could not be fixed independently. Two handlers, two fixes.
 *
 * <p><strong>FIX:</strong> catch the coercion failure at the boundary and
 * return a clean 400 that says which field was wrong, without the type, the
 * class path or the target type. On a DTO, the fix is a validation
 * annotation plus a handler that returns only the field names.
 */
@RestController
@RequestMapping("/api/transfers")
public class CoercionController {

    private final LabToggles labs;

    public CoercionController(LabToggles labs) {
        this.labs = labs;
    }

    /**
     * The request body, strictly typed.
     *
     * <p>A DTO rather than a {@code Map}, so the deserializer has a target
     * type to fail against — and so the failure message can leak it.
     */
    public static class TransferRequest {
        private Long fromAccountId;
        private Long toAccountId;
        private BigDecimal amount;
        private String note;

        public Long getFromAccountId() {
            return fromAccountId;
        }

        public void setFromAccountId(Long fromAccountId) {
            this.fromAccountId = fromAccountId;
        }

        public Long getToAccountId() {
            return toAccountId;
        }

        public void setToAccountId(Long toAccountId) {
            this.toAccountId = toAccountId;
        }

        public BigDecimal getAmount() {
            return amount;
        }

        public void setAmount(BigDecimal amount) {
            this.amount = amount;
        }

        public String getNote() {
            return note;
        }

        public void setNote(String note) {
            this.note = note;
        }
    }

    /**
     * A typed transfer request.
     *
     * <p><strong>LAB 24 (VULNERABLE):</strong> a malformed amount produces a
     * message-coercion exception whose message is returned verbatim.
     *
     * <p><strong>FIX:</strong> delete the vulnerable branch; the
     * {@code @ExceptionHandler} below then produces the clean response.
     */
    @PostMapping("/typed-send")
    public ResponseEntity<Map<String, Object>> typedSend(@RequestBody TransferRequest request) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("message", "Transfer accepted");
        out.put("from_account_id", request.getFromAccountId());
        out.put("to_account_id", request.getToAccountId());
        out.put("amount", request.getAmount());
        out.put("note", request.getNote());
        return ResponseEntity.ok(out);
    }

    /**
     * LAB 24's own handler for malformed bodies.
     *
     * <p><strong>LAB 24 (VULNERABLE):</strong> the exception's own message
     * is returned to the client, and it names the Java types and the field
     * path.
     *
     * <p><strong>FIX:</strong> return a generic message that names the
     * offending field but nothing else. The detail goes to the server log.
     */
    @ExceptionHandler({org.springframework.http.converter.HttpMessageNotReadableException.class})
    public ResponseEntity<Map<String, Object>> handleUnreadable(
            org.springframework.http.converter.HttpMessageNotReadableException ex) {

        if (labs.isEnabled("typecoercion")) {
            // LAB 24 (VULNERABLE): the deserializer's message, verbatim. It
            // names the target type (BigDecimal), the field (amount), the
            // value the client sent, and the application's own class path.
            //
            // FIX: delete this branch — the generic response below is the fix.
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("error", "Could not read the request body");
            out.put("detail", ex.getMessage());
            out.put("cause", ex.getCause() == null ? null : ex.getCause().toString());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(out);
        }

        // ---- FIX (the intended final state) ----
        org.slf4j.LoggerFactory.getLogger(CoercionController.class)
                .warn("Rejected a malformed transfer body", ex);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", "The request body was malformed"));
    }
}
