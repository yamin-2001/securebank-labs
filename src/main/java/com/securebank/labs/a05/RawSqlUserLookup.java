package com.securebank.labs.a05;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * <strong>LAB 10 (A05 — Injection): SQL injection.</strong>
 *
 * <p>This component builds a SQL statement by concatenating caller-supplied
 * values straight into the string, then executes it verbatim. A payload like
 * {@code admin' --} comments out the password predicate and returns the admin
 * row without a password check.
 *
 * <p><strong>FIX:</strong> use a parameterized statement. The intended end
 * state is the {@link #findByUsernameAndPasswordHash} method below — it binds
 * the values as JDBC parameters so the payload is treated as data, never as
 * SQL. Delete the vulnerable method and switch the caller to the
 * parameterized one.
 */
@Component
public class RawSqlUserLookup {

    private final JdbcTemplate jdbc;

    public RawSqlUserLookup(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * LAB 10 (VULNERABLE): the username is concatenated into the SQL string.
     *
     * <p>FIX: delete this method and use
     * {@link #findByUsernameAndPasswordHash(String, String)}.
     */
    public List<Map<String, Object>> findUserRaw(String username, String passwordHash) {
        String sql = "SELECT id, username, password_hash, email, full_name, role, created_at"
                + " FROM users WHERE username='" + username
                + "' AND password_hash='" + passwordHash + "'";
        return jdbc.queryForList(sql);
    }

    /**
     * ---- FIX (the intended final state) ----
     *
     * <p>Parameterized query: the username and the hash are bound as JDBC
     * parameters, so {@code admin' --} is matched as a literal username
     * instead of terminating the string.
     */
    public List<Map<String, Object>> findByUsernameAndPasswordHash(String username, String passwordHash) {
        String sql = "SELECT id, username, password_hash, email, full_name, role, created_at"
                + " FROM users WHERE username = ? AND password_hash = ?";
        return jdbc.queryForList(sql, username, passwordHash);
    }
}
