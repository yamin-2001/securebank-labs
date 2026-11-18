package com.securebank.labs.a06;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.securebank.core.AuthContext;
import com.securebank.domain.Transfer;
import com.securebank.labs.a05.NoteRenderer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Transfer endpoints.
 *
 * <p>Home to two labs, each in its own place:
 * <ul>
 *   <li><strong>LAB 13</strong> (A05) — stored XSS. The note is rendered as
 *       raw HTML by {@link NoteRenderer}; see
 *       {@link #html(List)}.</li>
 *   <li><strong>LAB 14</strong> (A06) — negative transfer amounts; see
 *       {@link TransferService}.</li>
 * </ul>
 *
 * <p>Lab 13's fix lives in the renderer, not here, so that the React UI and
 * this endpoint can never disagree.
 */
@RestController
@RequestMapping("/api/transfers")
public class TransferController {

    private final TransferService transferService;
    private final NoteRenderer notes;

    public TransferController(TransferService transferService, NoteRenderer notes) {
        this.transferService = transferService;
        this.notes = notes;
    }

    /**
     * Send money.
     *
     * <p><strong>LAB 14:</strong> a negative amount creates money.
     */
    @PostMapping("/send")
    public ResponseEntity<Map<String, Object>> send(@RequestBody Map<String, Object> body) {
        Long fromId = toLong(body.get("from_account_id"));
        Long toId = toLong(body.get("to_account_id"));
        BigDecimal amount = toDecimal(body.get("amount"));
        String note = body.get("note") == null ? null : String.valueOf(body.get("note"));
        Long callerId = AuthContext.userId().orElse(null);

        Transfer transfer = transferService.send(fromId, toId, amount, note, callerId);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("message", "Transfer sent");
        out.put("transfer", TransferService.view(transfer));
        return ResponseEntity.ok(out);
    }

    /**
     * The transfers visible to the caller.
     */
    @GetMapping("/history")
    public List<Map<String, Object>> history() {
        Long callerId = AuthContext.userId().orElse(0L);
        return transferService.visibleTo(callerId).stream()
                .map(TransferService::view)
                .toList();
    }

    /**
     * LAB 13: the transfers page, rendered as HTML.
     *
     * <p>This is the same markup the React UI injects with
     * {@code dangerouslySetInnerHTML}, produced by the same
     * {@link NoteRenderer}. On the vulnerable build a note containing
     * {@code <img src=x onerror=...>} comes back as live markup; on the
     * fixed build it comes back escaped.
     *
     * <p>This endpoint exists so the XSS lab is verifiable over plain HTTP.
     */
    @GetMapping(value = "/html", produces = MediaType.TEXT_HTML_VALUE)
    public String html() {
        Long callerId = AuthContext.userId().orElse(0L);
        List<Transfer> visible = transferService.visibleTo(callerId);

        StringBuilder out = new StringBuilder();
        out.append("<ul class=\"txn-list\">\n");
        for (Transfer transfer : visible) {
            out.append("  <li class=\"txn\">\n");
            out.append("    <span class=\"txn-amount\">")
                    .append(transfer.getAmount())
                    .append("</span>\n");
            out.append("    ").append(notes.render(transfer.getNote())).append("\n");
            out.append("  </li>\n");
        }
        out.append("</ul>\n");
        return out.toString();
    }

    private static Long toLong(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Number n) {
            return n.longValue();
        }
        try {
            return Long.valueOf(String.valueOf(value));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static BigDecimal toDecimal(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof BigDecimal d) {
            return d;
        }
        if (value instanceof Number n) {
            return new BigDecimal(n.toString());
        }
        try {
            return new BigDecimal(String.valueOf(value));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @ExceptionHandler(TransferService.TransferException.class)
    public ResponseEntity<Map<String, Object>> rejected(TransferService.TransferException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", e.getMessage()));
    }
}
