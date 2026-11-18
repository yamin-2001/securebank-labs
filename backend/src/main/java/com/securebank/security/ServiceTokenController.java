package com.securebank.security;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Issues a service token — a credential that names no user.
 *
 * <p>This exists so that <strong>Lab 25</strong> (fail-open authentication)
 * can be exploited honestly:
 *
 * <ul>
 *   <li>the attacker does <em>not</em> need the signing secret, so Lab 25
 *       is independent of Lab 8 (the hardcoded secret);</li>
 *   <li>the attacker does <em>not</em> need to forge anything, so Lab 25 is
 *       independent of Lab 21 (the {@code alg:none} parser).</li>
 * </ul>
 *
 * <p>Service tokens are a real pattern — webhooks, batch jobs, partner
 * integrations, and tokens left behind by deleted users. The bug is not the
 * existence of such a token. The bug is what the server does when a request
 * arrives with a valid token that names nobody: instead of rejecting it, the
 * filter falls through to a default identity of {@code user_id = 1}, which is
 * the admin.
 *
 * <p><strong>This endpoint is a lab convenience.</strong> A real deployment
 * would not expose it. It is deliberately outside the {@code /api/auth/**}
 * namespace so it cannot be confused with the login endpoints.
 */
@RestController
@RequestMapping("/api/service")
public class ServiceTokenController {

    private final LabJwtService jwt;

    public ServiceTokenController(LabJwtService jwt) {
        this.jwt = jwt;
    }

    /**
     * Mint a token for a named service.
     */
    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> token(@RequestBody Map<String, String> body) {
        String name = body.getOrDefault("service", "batch-settlement");

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("token", jwt.issueServiceToken(name));
        out.put("service", name);
        out.put("message", "Service token issued. It carries no user identity.");
        return ResponseEntity.ok(out);
    }
}
