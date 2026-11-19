package com.securebank.security;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import com.securebank.core.LabToggles;

/**
 * The JWT signing secret.
 *
 * <p><strong>LAB 8 (A04 — Cryptographic Failures).</strong>
 *
 * <p><strong>FIXED.</strong> The secret used to be a hardcoded literal in
 * this file, and {@link #logSecretAtStartup} wrote it to the log at startup.
 * Anyone who could read the source, the logs, or the {@code .env} file could
 * forge a token for any user — including admin — and authenticate without a
 * password.
 *
 * <p>The secret now comes from the environment:
 *
 * <pre>{@code
 * python3 -c "import secrets; print(secrets.token_hex(32))"
 * }</pre>
 *
 * <p>Set it as {@code APP_JWT_SECRET} in the environment, or as the
 * {@code app.jwt-secret} system property. The secret is never logged, and it
 * never appears in the source tree.
 *
 * <p>If neither is configured the app still boots, with a random secret
 * generated for the lifetime of the process. That is not a secret anyone can
 * guess, but it does mean every restart invalidates the tokens already
 * issued — a real deployment should fail to start instead of guessing.
 */
public final class JwtKeys {

    /** Where a real deployment reads the secret from. */
    public static final String SECRET_ENV_VAR = "APP_JWT_SECRET";

    /** The system-property equivalent of {@link #SECRET_ENV_VAR}. */
    public static final String SECRET_PROPERTY = "app.jwt-secret";

    /**
     * The secret in use.
     *
     * <p>Read from the environment, then from the system properties, then
     * from a random per-process fallback. Never hardcoded, never logged.
     */
    public static String secret(LabToggles labs) {
        String fromEnv = System.getenv(SECRET_ENV_VAR);
        if (fromEnv != null && !fromEnv.isBlank()) {
            return fromEnv;
        }

        String fromProperty = System.getProperty(SECRET_PROPERTY);
        if (fromProperty != null && !fromProperty.isBlank()) {
            return fromProperty;
        }

        // No secret configured — a random one for the lifetime of the process.
        // It must be the same for the lifetime of the process, or issued
        // tokens would not verify.
        return fallbackSecret();
    }

    /**
     * A stable, unguessable fallback used only when no secret is configured.
     *
     * <p>Held in a static field so every call returns the same value for the
     * lifetime of the process — a token issued now must still verify on the
     * next request.
     */
    private static final String FALLBACK_SECRET = randomSecret();

    private static String randomSecret() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static String fallbackSecret() {
        return FALLBACK_SECRET;
    }

    /**
     * LAB 8 (FIXED): the secret is no longer written to the log.
     *
     * <p>The call is kept so the startup wiring does not change, but it now
     * reports only that a secret is configured — never its value.
     */
    public static void logSecretAtStartup(LabToggles labs, org.slf4j.Logger log) {
        if (System.getenv(SECRET_ENV_VAR) != null || System.getProperty(SECRET_PROPERTY) != null) {
            log.info("JWT signing secret loaded from the environment");
        } else {
            log.warn("No JWT signing secret configured — using a random one for this "
                    + "process only. Set {} before deploying.", SECRET_ENV_VAR);
        }
    }

    private JwtKeys() {
    }
}
