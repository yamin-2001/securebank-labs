package com.securebank.security;

import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * The CORRECT JWT parser — this is what the fixed Lab 21 must use.
 *
 * <p>jjwt's {@code parseSignedClaims()} requires a valid signature over the
 * declared algorithm. It rejects {@code alg:none} and any algorithm other than
 * the one the key was built for. That is precisely the behaviour a correct
 * implementation must have, so this class is both the safe default and the
 * reference fix for Lab 21.
 */
public class SecureJwtService {

    private final SecretKey key;

    public SecureJwtService(String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Verify and parse a token.
     *
     * @throws JwtException if the signature is invalid, the token is unsecured
     *                      ({@code alg:none}), or the algorithm does not match.
     */
    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /** Issue a signed HS256 token. */
    public String issue(Long userId, String username, String role) {
        return Jwts.builder()
                .claim("user_id", userId)
                .claim("username", username)
                .claim("role", role)
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }
}
