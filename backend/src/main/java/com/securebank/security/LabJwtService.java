package com.securebank.security;

import java.nio.charset.StandardCharsets;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * Issues and parses JWTs.
 *
 * <p>Holds the two JWT labs, each with its own fix location:
 * <ul>
 *   <li><strong>Lab 8 (FIXED)</strong> — the signing secret used to be a
 *       hardcoded literal in the source tree; it now comes from the
 *       environment. See {@link JwtKeys#secret()}.</li>
 *   <li><strong>Lab 21 (FIXED)</strong> — {@link #parse(String)} used to be
 *       able to hand the token to a hand-rolled parser that never inspected
 *       the {@code alg} header and never verified the signature.</li>
 * </ul>
 *
 * <p>jjwt cannot help with Lab 21's exploit: {@code JwtBuilder} exposes only
 * {@code signWith(...)} (no unsecured builder) and {@code parseSignedClaims}
 * rejects unsecured tokens by design. The vulnerable parser therefore had to
 * be hand-written — which is exactly the mistake being taught: you wrote the
 * JWT parser yourself and forgot to check {@code alg}.
 */
public class LabJwtService {

    private final SecureJwtService secureParser;

    public LabJwtService() {
        this.secureParser = new SecureJwtService(JwtKeys.secret());
    }

    /** Issue a token for the given principal. */
    public String issue(Long userId, String username, String role) {
        return Jwts.builder()
                .claim("user_id", userId)
                .claim("username", username)
                .claim("role", role)
                .signWith(Keys.hmacShaKeyFor(
                                JwtKeys.secret().getBytes(StandardCharsets.UTF_8)),
                        Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Issue a token that names no user.
     *
     * <p>This is the real-world shape of Lab 25's bug: a <em>service</em>
     * token — a webhook credential, a batch job's token, a token for a user
     * that has been deleted. It is perfectly valid and perfectly signed; it
     * simply does not say who the bearer is.
     *
     * <p>The endpoint that hands these out is a lab convenience, not
     * something a real bank would ship. It exists so the exploit can be
     * expressed honestly: the attacker does not need the signing secret (so
     * Lab 25 stays independent of Lab 8), and does not need a forged token
     * (so it stays independent of Lab 21). They simply present a valid
     * credential that names nobody.
     */
    public String issueServiceToken(String serviceName) {
        return Jwts.builder()
                .claim("service", serviceName)
                .claim("role", "customer")
                .signWith(Keys.hmacShaKeyFor(
                                JwtKeys.secret().getBytes(StandardCharsets.UTF_8)),
                        Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Parse a token.
     *
     * <p><strong>LAB 21 (FIXED):</strong> the token used to be handed to a
     * hand-rolled parser that never inspected the {@code alg} header and
     * never verified the signature, so an {@code alg:none} token — a
     * signature of nothing — was accepted as if it were signed.
     *
     * <p>The token now always goes through {@code secureParser}, which pins
     * HS256 and verifies the signature. {@code parseSignedClaims()} rejects
     * {@code alg:none} and every algorithm other than HS256.
     */
    public Claims parse(String token) {
        return secureParser.parse(token);
    }
}
