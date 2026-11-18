package com.securebank.labs.a01;

import java.util.List;
import java.util.Map;

import com.securebank.core.AuthContext;
import com.securebank.domain.Account;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Account endpoints.
 *
 * <p>Home of <strong>LAB 1 (A01): IDOR</strong> — see {@link AccountService}.
 */
@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountService accounts;
    private final SsrfStatementService statements;

    public AccountController(AccountService accounts, SsrfStatementService statements) {
        this.accounts = accounts;
        this.statements = statements;
    }

    /** The caller's own accounts. */
    @GetMapping
    public List<Map<String, Object>> myAccounts() {
        Long userId = AuthContext.userId().orElse(0L);
        return accounts.listAccounts(userId).stream().map(AccountController::view).toList();
    }

    /**
     * LAB 1: a single account by id.
     *
     * <p>Swap the id in the URL to read another customer's account.
     */
    @GetMapping("/{id}")
    public Map<String, Object> getAccount(@PathVariable Long id) {
        Long callerId = AuthContext.userId().orElse(null);
        return view(accounts.getAccount(id, callerId));
    }

    /**
     * LAB 3: "email me my statement" to a callback URL.
     *
     * <p>Supply an internal URL as {@code callback_url} and the server will
     * fetch it for you and hand back what it found.
     */
    @PostMapping("/statement-email")
    public Map<String, Object> statementEmail(@RequestBody Map<String, Object> body) {
        Long accountId = toLong(body.get("account_id"));
        String callbackUrl = body.get("callback_url") == null
                ? null : String.valueOf(body.get("callback_url"));
        return statements.sendStatement(accountId, callbackUrl);
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

    static Map<String, Object> view(Account account) {        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("id", account.getId());
        body.put("account_number", account.getAccountNumber());
        body.put("sort_code", account.getSortCode());
        body.put("balance", account.getBalance());
        body.put("currency", account.getCurrency());
        body.put("owner_id", account.getOwnerId());
        return body;
    }

    @ExceptionHandler(AccountService.AccountNotFoundException.class)
    public ResponseEntity<Map<String, Object>> notFound(AccountService.AccountNotFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", e.getMessage()));
    }

    @ExceptionHandler(AccountService.AccountForbiddenException.class)
    public ResponseEntity<Map<String, Object>> forbidden(AccountService.AccountForbiddenException e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", e.getMessage()));
    }
}
