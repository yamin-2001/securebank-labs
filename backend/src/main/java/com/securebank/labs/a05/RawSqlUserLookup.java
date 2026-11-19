package com.securebank.labs.a05;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * <strong>LAB 10 (A05 — Injection): SQL injection.</strong>
 *
 * <p>This component builds a SQL statement by concatenating a caller-supplied
 * value straight into the string, then executes it verbatim. A payload like
 * {@code admin' --} comments out the rest of the WHERE clause and returns the
 * admin row with no password check.
 *
 * <p>Note that the password is <em>not</em> part of the SQL. The password
 * check lives in Java (see {@code AuthController}). That keeps this lab
 * independent of Lab 7 — fixing the hashing does not affect the injection,
 * and fixing the injection does not affect the hashing.
 *
 * <p><strong>FIX:</strong> use a parameterized statement — bind the username
 * as a JDBC parameter so the payload is treated as data, never as SQL.
 */
@Component
public class RawSqlUserLookup {

    private final JdbcTemplate jdbc;

    public RawSqlUserLookup(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * LAB 10 (VULNERABLE): the username is concatenated into the SQL string.
     */
    public List<Map<String, Object>> findUserRaw(String username) {
        String sql = "SELECT id, username, password_hash, email, full_name, role, created_at"
                + " FROM users WHERE username='" + username + "'";
        return jdbc.queryForList(sql);
    }
}
