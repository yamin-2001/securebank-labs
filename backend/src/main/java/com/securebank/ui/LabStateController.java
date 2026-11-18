package com.securebank.ui;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Lab state management.
 *
 * <p>Exploiting a lab mutates the database: Lab 14 moves money, Lab 15
 * promotes a customer to admin, Lab 13 stores a note. Without a reset, the
 * state drifts as you work, and a lab you already fixed can start failing
 * again (or vice versa) for reasons that have nothing to do with your fix.
 *
 * <p>This endpoint re-runs {@code data.sql}, which is written to be
 * idempotent: it restores the seeded balances, the seeded roles, and the
 * seeded password hashes. It is a lab convenience — a real deployment would
 * not expose it — and it deliberately lives outside {@code /api/auth/**}.
 */
@RestController
public class LabStateController {

    private final JdbcTemplate jdbc;

    public LabStateController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * Restore the seeded state.
     *
     * <p>The schema is left alone; only the data is re-seeded.
     */
    @PostMapping("/api/lab/reset")
    @Transactional
    public Map<String, Object> reset() {
        ResourceDatabasePopulator populator =
                new ResourceDatabasePopulator(new ClassPathResource("data.sql"));
        populator.execute(jdbc.getDataSource());

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("reset", true);
        out.put("message", "Seeded state restored — balances, roles and password hashes.");
        return out;
    }

    /**
     * The current state, for the UI's status strip.
     */
    @GetMapping("/api/lab/state")
    public Map<String, Object> state() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("users", jdbc.queryForObject("SELECT count(*) FROM users", Integer.class));
        out.put("accounts", jdbc.queryForObject("SELECT count(*) FROM accounts", Integer.class));
        out.put("transfers", jdbc.queryForObject("SELECT count(*) FROM transfers", Integer.class));
        out.put("balance_total", jdbc.queryForObject(
                "SELECT COALESCE(sum(balance), 0) FROM accounts", java.math.BigDecimal.class));
        return out;
    }
}
