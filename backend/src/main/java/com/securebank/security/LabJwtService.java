package com.securebank.security;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * Issues and parses JWTs.
 *
 * <p>Holds the two JWT labs, each with its own fix location:
 * <ul>
 *   <li><strong>Lab 8</strong> — the signing secret is the hardcoded literal
 *       {@link JwtKeys#HARDCODED_SECRET}.</li>
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
     * <p><strong>LAB 21 (VULNERABLE):</strong> the token is handed to
     * {@link #parseWithoutAlgorithmCheck(String)}, which never verifies the
     * signature and never checks the {@code alg} header.
     *
     * <p>A token that declares HS256 is judged by the signature check, so
     * Lab 8 (the hardcoded secret) and Lab 21 (the missing alg check) stay
     * independent: exploiting one does not accidentally exploit or break the
     * other.
     */
    public Claims parse(String token) {
        // LAB 21 (VULNERABLE): hand-rolled parse, no alg check, no signature check.
        if (declaresAlgNone(token)) {
            return parseWithoutAlgorithmCheck(token);
        }
        // Lab 8 default: pin HS256 and verify the signature.
        return secureParser.parse(token);
    }

    /**
     * Does the token's header declare {@code alg: none}?
     *
     * <p>This is deliberately narrow. The bug being taught in Lab 21 is
     * "the parser never looks at {@code alg}", so the vulnerable path must
     * apply to the tokens that exploit that bug — unsecured ones. A token
     * that declares HS256 is a different attack (Lab 8) and is judged by the
     * signature check.
     */
    private boolean declaresAlgNone(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            return false;
        }
        try {
            byte[] raw = Base64.getUrlDecoder().decode(parts[0]);
            String header = new String(raw, StandardCharsets.UTF_8);
            return header.contains("\"none\"");
        } catch (IllegalArgumentException e) {
            return false;
        }
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
