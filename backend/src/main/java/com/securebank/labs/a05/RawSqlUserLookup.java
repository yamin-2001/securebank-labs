package com.securebank.labs.a05;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * <strong>LAB 10 (A05 — Injection): SQL injection.</strong>
 *
 * <p><strong>FIXED.</strong> This component used to build a SQL statement by
 * concatenating a caller-supplied value straight into the string, then
 * execute it verbatim. A payload like {@code admin' --} commented out the
 * rest of the WHERE clause and returned the admin row with no password
 * check.
 *
 * <p>The username is now bound as a JDBC parameter, so the payload is
 * treated as data and can never be syntax.
 *
 * <p>Note that the password is <em>not</em> part of the SQL. The password
 * check lives in Java (see {@code AuthController}). That keeps this lab
 * independent of Lab 7 — fixing the hashing does not affect the injection,
 * and fixing the injection does not affect the hashing.
 */
@Component
public class RawSqlUserLookup {

    private final JdbcTemplate jdbc;

    public RawSqlUserLookup(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * Parameterized query: the username is bound as a JDBC parameter, so
     * {@code admin' --} is matched as a literal username instead of
     * terminating the string.
     */
    public List<Map<String, Object>> findByUsername(String username) {
        String sql = "SELECT id, username, password_hash, email, full_name, role, created_at"
                + " FROM users WHERE username = ?";
        return jdbc.queryForList(sql, username);
    }
}
