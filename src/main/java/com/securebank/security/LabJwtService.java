package com.securebank.security;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import com.securebank.core.LabToggles;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * Issues and parses JWTs.
 *
 * <p>Holds the two JWT labs, each with its own fix location:
 * <ul>
 *   <li><strong>Lab 8</strong> — the signing secret is the hardcoded literal
 *       {@link JwtKeys#SECRET}.</li>
 *   <li><strong>Lab 21</strong> — {@link #parse(String)} may hand the token to
 *       a hand-rolled parser that never inspects the {@code alg} header and
 *       never verifies the signature.</li>
 * </ul>
 *
 * <p>jjwt cannot help with Lab 21's exploit: {@code JwtBuilder} exposes only
 * {@code signWith(...)} (no unsecured builder) and {@code parseSignedClaims}
 * rejects unsecured tokens by design. The vulnerable parser therefore has to
 * be hand-written — which is exactly the mistake being taught: you wrote the
 * JWT parser yourself and forgot to check {@code alg}.
 */
public class LabJwtService {

    private final LabToggles labs;
    private final SecureJwtService secureParser;

    public LabJwtService(LabToggles labs) {
        this.labs = labs;
        this.secureParser = new SecureJwtService(JwtKeys.SECRET);
    }

    /** Issue a token for the given principal. */
    public String issue(Long userId, String username, String role) {
        return Jwts.builder()
                .claim("user_id", userId)
                .claim("username", username)
                .claim("role", role)
                .signWith(Keys.hmacShaKeyFor(JwtKeys.SECRET.getBytes(StandardCharsets.UTF_8)),
                        Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Parse a token.
     *
     * <p><strong>LAB 21 (VULNERABLE):</strong> when the {@code jwtalgnone}
     * toggle is armed, the token is handed to
     * {@link #parseWithoutAlgorithmCheck(String)}, which never verifies the
     * signature and never checks the {@code alg} header.
     *
     * <p><strong>FIX:</strong> delete the vulnerable branch and always use
     * {@code secureParser}. {@code parseSignedClaims()} rejects {@code alg:none}
     * and every algorithm other than HS256.
     */
    public Claims parse(String token) {
        if (labs.isEnabled("jwtalgnone")) {
            // LAB 21 (VULNERABLE): hand-rolled parse, no alg check, no signature check.
            // FIX: delete this branch — the secureParser below is the correct answer.
            return parseWithoutAlgorithmCheck(token);
        }
        // FIXED (and the Lab 8 default): pin HS256 and verify the signature.
        return secureParser.parse(token);
    }

    /**
     * The deliberately-broken parser behind Lab 21.
     *
     * <p>Note what is NOT here, and is not an oversight:
     * <ul>
     *   <li>no check that the header declares {@code HS256}</li>
     *   <li>no check that the token has three parts</li>
     *   <li>no signature verification whatsoever</li>
     * </ul>
     */
    private Claims parseWithoutAlgorithmCheck(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            throw new LabMalformedTokenException("Token is not a JWT");
        }
        Map<String, Object> payload = decodeJson(parts[1]);
        return Jwts.claims(payload);
    }

    /** Decode a base64url-encoded JSON object into a map. */
    private Map<String, Object> decodeJson(String segment) {
        try {
            byte[] raw = Base64.getUrlDecoder().decode(segment);
            String json = new String(raw, StandardCharsets.UTF_8);
            Map<String, Object> map = new LinkedHashMap<>();
            int i = 0;
            while (i < json.length()) {
                int keyStart = json.indexOf('"', i);
                if (keyStart < 0) {
                    break;
                }
                int keyEnd = json.indexOf('"', keyStart + 1);
                if (keyEnd < 0) {
                    break;
                }
                String key = json.substring(keyStart + 1, keyEnd);
                int colon = json.indexOf(':', keyEnd);
                if (colon < 0) {
                    break;
                }
                int valueStart = colon + 1;
                while (valueStart < json.length() && Character.isWhitespace(json.charAt(valueStart))) {
                    valueStart++;
                }
                int valueEnd = valueStart;
                if (valueStart < json.length() && json.charAt(valueStart) == '"') {
                    valueEnd = json.indexOf('"', valueStart + 1);
                    if (valueEnd < 0) {
                        break;
                    }
                    map.put(key, json.substring(valueStart + 1, valueEnd));
                    i = valueEnd + 1;
                } else {
                    while (valueEnd < json.length() && json.charAt(valueEnd) != ',' && json.charAt(valueEnd) != '}') {
                        valueEnd++;
                    }
                    String rawValue = json.substring(valueStart, valueEnd).trim();
                    map.put(key, coerce(rawValue));
                    i = valueEnd;
                }
                while (i < json.length() && json.charAt(i) != ',') {
                    i++;
                }
                i++;
            }
            return map;
        } catch (IllegalArgumentException e) {
            throw new LabMalformedTokenException("Token is not valid base64url", e);
        }
    }

    private Object coerce(String raw) {
        if ("true".equals(raw)) {
            return Boolean.TRUE;
        }
        if ("false".equals(raw)) {
            return Boolean.FALSE;
        }
        if ("null".equals(raw)) {
            return null;
        }
        try {
            return Long.valueOf(raw);
        } catch (NumberFormatException ignored) {
            return raw;
        }
    }
}
