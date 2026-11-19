package com.securebank.labs.a05;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * <strong>LAB 10 (A05 — Injection): SQL injection in the transfer search.</strong>
 *
 * <p>The login-bypass half of this lab lives in
 * {@code labs/a07/AuthController}; this is the data-dump half: a search box
 * whose query is built by concatenating the search term into the SQL
 * string. A {@code UNION SELECT} payload turns it into a read of the
 * {@code users} table.
 *
 * <p><strong>FIX:</strong> use a parameterized query — bind the values as
 * JDBC parameters so the payload is data, never SQL.
 */
@RestController
@RequestMapping("/api/transfers")
public class InjectionController {

    private final JdbcTemplate jdbc;

    public InjectionController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * Search transfers by note.
     *
     * <p><strong>LAB 10 (VULNERABLE):</strong> the search term is pasted
     * into the statement.
     */
    @GetMapping("/search")
    public List<Map<String, Object>> search(@RequestParam("q") String query) {
        String sql = "SELECT id, from_account_id, to_account_id, amount, note, status"
                + " FROM transfers WHERE note LIKE '%" + query + "%'";
        return jdbc.queryForList(sql);
    }

    /**
     * A harmless companion endpoint, used by the UI to list transfers.
     */
    @GetMapping
    public List<Map<String, Object>> list() {
        return jdbc.queryForList(
                "SELECT id, from_account_id, to_account_id, amount, note, status"
                        + " FROM transfers ORDER BY id");
    }

    /** A small helper the UI can use for the transfer form. */
    @GetMapping("/meta")
    public Map<String, Object> meta() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("accounts", jdbc.queryForList(
                "SELECT id, account_number, balance FROM accounts ORDER BY id"));
        body.put("currencies", List.of("GBP", "EUR", "USD"));
        return body;
    }
}
