package com.securebank.security;

/**
 * The JWT signing secret.
 *
 * <p><strong>LAB 8 (A04 — Cryptographic Failures).</strong> The secret is a
 * hardcoded literal, and {@link #SECRET} is logged at startup. Anyone who can
 * read the source, the logs, or the {@code .env} file can forge a token for
 * any user — including admin — and authenticate without a password.
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
    public static final String SECRET = "hardcoded-jwt-secret-do-not-ship-2024";

    /** LAB 8 (VULNERABLE): logged at startup so anyone with log access can read it. */
    public static void logSecretAtStartup(org.slf4j.Logger log) {
        log.warn("JWT signing secret is: {}", SECRET);
    }

    private JwtKeys() {
    }
}
