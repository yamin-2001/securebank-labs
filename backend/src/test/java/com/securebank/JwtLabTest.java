package com.securebank;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import com.securebank.security.JwtKeys;
import com.securebank.security.LabJwtService;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.Test;

/**
 * The JWT labs.
 *
 * <p>Labs 8, 21 and 25 all live in the same two classes, so they are easy
 * to break by accident. These tests pin the behaviour each of them needs:
 *
 * <ul>
 *   <li>Lab 21: the vulnerable parser accepts an {@code alg:none} token.</li>
 *   <li>Lab 25: a token that names no user parses successfully — the
 *       fail-open is in the filter, not the parser, so the two fixes stay
 *       independent.</li>
 * </ul>
 */
class JwtLabTest {

    private static LabJwtService service() {
        return new LabJwtService();
    }

    /** Build an unsigned {@code alg:none} token by hand. */
    private static String algNoneToken(Map<String, Object> claims) {
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(toJson(claims).getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".";
    }

    private static String toJson(Map<String, Object> claims) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            if (!first) {
                sb.append(",");
            }
            first = false;
            sb.append('"').append(entry.getKey()).append("\":");
            Object value = entry.getValue();
            if (value instanceof Number n) {
                sb.append(n);
            } else {
                sb.append('"').append(value).append('"');
            }
        }
        return sb.append("}").toString();
    }

    @Test
    void lab21TheVulnerableParserAcceptsAnAlgNoneToken() {
        LabJwtService jwt = service();
        Claims claims = jwt.parse(algNoneToken(Map.of("user_id", 1L, "role", "admin")));
        assertThat(claims.get("role", String.class)).isEqualTo("admin");
    }

    @Test
    void lab25AServiceTokenIsValidButNamesNoUser() {
        // This is the whole point of Lab 25: the token parses fine, so the
        // fix has to live in the filter — which means Lab 21's fix cannot
        // accidentally fix Lab 25, and vice versa.
        LabJwtService jwt = service();
        Claims claims = jwt.parse(jwt.issueServiceToken("batch-settlement"));

        assertThat(claims.get("service", String.class)).isEqualTo("batch-settlement");
        assertThat(claims.get("user_id")).isNull();
        assertThat(claims.get("username")).isNull();
    }

    @Test
    void aServiceTokenIsSignedWithTheRealSecret() {
        // The service token has to pass signature verification, so the
        // fail-open is reached with a token the server itself issued.
        LabJwtService jwt = service();
        Claims claims = jwt.parse(jwt.issueServiceToken("webhook"));

        assertThat(claims.get("role", String.class)).isEqualTo("customer");
        assertThat(JwtKeys.secret()).isNotEmpty();
    }

    @Test
    void aUserTokenNamesItsUser() {
        LabJwtService jwt = service();
        Claims claims = jwt.parse(jwt.issue(2L, "alice", "customer"));

        assertThat(claims.get("user_id", Long.class)).isEqualTo(2L);
        assertThat(claims.get("username", String.class)).isEqualTo("alice");
    }
}
