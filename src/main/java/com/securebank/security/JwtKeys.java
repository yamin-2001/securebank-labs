package com.securebank.security;

import com.securebank.core.LabToggles;

/**
 * The JWT signing secret.
 *
 * <p><strong>LAB 8 (A04 — Cryptographic Failures).</strong> The secret is a
 * hardcoded literal, and {@link #logSecretAtStartup} writes it to the log at
 * startup. Anyone who can read the source, the logs, or the {@code .env}
 * file can forge a token for any user — including admin — and authenticate
 * without a password.
 *
 * <p><strong>FIX:</strong> read the secret from the environment (or a secret
 * manager), never hardcode it, never log it, and rotate it to a
 * cryptographically random value:
 *
 * <pre>{@code
 * python3 -c "import secrets; print(secrets.token_hex(32))"
 * }</pre>
 *
 * <p>Lab 8 and Lab 21 share this constant on purpose — they are separate
 * labs with separate fixes, but they attack the same secret.
 */
public final class JwtKeys {

    /**
     * LAB 8 (VULNERABLE): hardcoded signing secret.
     *
     * <p>FIX: {@code System.getenv("APP_JWT_SECRET")} (and stop logging it).
     *
     * <p>Note on length: jjwt refuses to sign with an HMAC key shorter than
     * 256 bits (RFC 7518 §3.2), so the secret cannot be the literal string
     * {@code "secret"}. It is 32 bytes of hardcoded, publicly-readable text —
     * still trivially guessable and still in version control, which is the
     * entire point of the lab.
     */
    public static final String HARDCODED_SECRET = "hardcoded-jwt-secret-do-not-ship-2024";

    /** Where a real deployment would read the secret from. */
    public static final String SECRET_ENV_VAR = "APP_JWT_SECRET";

    /**
     * The secret in use.
     *
     * <p>While the {@code jwtsecret} lab is armed, this is the hardcoded
     * literal. Once it is disarmed, the secret comes from the environment —
     * which is what the fixed code does.
     */
    public static String secret(LabToggles labs) {
        if (labs.isEnabled("jwtsecret")) {
            // LAB 8 (VULNERABLE): the secret is a literal in the source tree.
            return HARDCODED_SECRET;
        }
        // FIXED: read it from the environment.
        String fromEnv = System.getenv(SECRET_ENV_VAR);
        if (fromEnv != null && !fromEnv.isBlank()) {
            return fromEnv;
        }
        // No secret configured — fall back to a stable value nobody can guess,
        // so the app still boots and still issues verifiable tokens. A real
        // deployment should fail to start instead.
        return fallbackSecret;
    }

    /**
     * A stable, unguessable fallback used only when {@code APP_JWT_SECRET} is
     * not set. It must be the same for the lifetime of the process, or issued
     * tokens would not verify.
     */
    private static final String fallbackSecret =
            "no-secret-configured-" + java.util.UUID.randomUUID();

    /** LAB 8 (VULNERABLE): logged at startup so anyone with log access can read it. */
    public static void logSecretAtStartup(LabToggles labs, org.slf4j.Logger log) {
        if (labs.isEnabled("jwtsecret")) {
            log.warn("JWT signing secret is: {}", secret(labs));
        }
    }

    private JwtKeys() {
    }
}
