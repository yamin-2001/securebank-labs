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
 * whose query was built by concatenating the search term into the SQL
 * string. A {@code UNION SELECT} payload turned it into a read of the
 * {@code users} table.
 *
 * <p><strong>FIXED:</strong> the search term is bound as a JDBC parameter,
 * so it is data and never syntax. See {@link RawSqlUserLookup} for the same
 * fix on the login query.
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
     * <p><strong>LAB 10 (FIXED):</strong> the search term is bound as a
     * JDBC parameter, so it is data and never syntax. A
     * {@code ' UNION SELECT ...} payload is matched as a literal substring
     * instead of terminating the statement.
     */
    @GetMapping("/search")
    public List<Map<String, Object>> search(@RequestParam("q") String query) {
        String sql = "SELECT id, from_account_id, to_account_id, amount, note, status"
                + " FROM transfers WHERE note LIKE ?";
        return jdbc.queryForList(sql, "%" + query + "%");
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
