package com.securebank.labs.a01;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.securebank.domain.User;
import com.securebank.domain.repo.UserRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Administrative endpoints.
 *
 * <p>Home of <strong>LAB 2 (A01 — Broken Access Control): missing role
 * check</strong>. The endpoint itself performs no authorization; the whole
 * of the protection is supposed to live in the Spring Security matcher
 * configuration. See
 * {@code SecurityConfig#apiChain}:
 *
 * <pre>{@code
 * // LAB 2 (VULNERABLE): authenticated, but NO role check.
 * .requestMatchers("/api/admin/**").authenticated()
 * }</pre>
 *
 * <p><strong>FIX:</strong> change that matcher to
 * {@code .hasRole("ADMIN")}. Nothing in this file needs to change — that is
 * the point: the vulnerability is a <em>missing</em> check, so the fix is the
 * addition of one line elsewhere.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final UserRepository users;
    private final AccountService accounts;

    public AdminController(UserRepository users, AccountService accounts) {
        this.users = users;
        this.accounts = accounts;
    }

    /**
     * Every user in the system, including password hashes.
     *
     * <p>LAB 2: reachable by any authenticated customer.
     */
    @GetMapping("/users")
    public List<Map<String, Object>> allUsers() {
        return users.findAll().stream().map(AdminController::viewUser).toList();
    }

    /**
     * Every account in the system, including other customers' balances.
     *
     * <p>LAB 2: reachable by any authenticated customer.
     */
    @GetMapping("/accounts")
    public List<Map<String, Object>> allAccounts() {
        return accounts.listAllAccounts().stream().map(AccountController::view).toList();
    }

    static Map<String, Object> viewUser(User user) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", user.getId());
        body.put("username", user.getUsername());
        body.put("email", user.getEmail());
        body.put("full_name", user.getFullName());
        body.put("role", user.getRole());
        body.put("password_hash", user.getPasswordHash());
        body.put("created_at", user.getCreatedAt());
        return body;
    }
}
