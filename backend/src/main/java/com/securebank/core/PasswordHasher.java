package com.securebank.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.springframework.stereotype.Component;

/**
 * Password hashing.
 *
 * <p><strong>LAB 7 (A04 — Cryptographic Failures).</strong>
 *
 * <p><strong>FIXED.</strong> This class used to hash with unsalted MD5
 * while the {@code md5hash} lab was armed. It now always hashes with
 * PBKDF2-HMAC-SHA256 and a per-user random salt, and the seeded rows in
 * {@code data.sql} have been re-seeded to match.
 *
 * <p>{@link #matches(String, String)} still accepts the legacy MD5 format,
 * so a database can hold a mix of old and new hashes while you migrate the
 * remaining rows. Re-hash on successful login.
 *
 * <p>Note: fixing this does <strong>not</strong> fix Lab 10. The SQL comment
 * in the login-bypass payload removes the password predicate entirely, so
 * the injection still works whatever the hashing algorithm.
 */
@Component
public class PasswordHasher {

    public PasswordHasher() {
    }

    /**
     * Hash a password.
     *
     * <p><strong>LAB 7 (FIXED):</strong> PBKDF2-HMAC-SHA256 with a fresh
     * random salt per password. The MD5 branch is gone — unsalted MD5 is a
     * rainbow table lookup, not password hashing.
     */
    public String hash(String password) {
        String salt = randomSalt();
        return pbkdf2(password == null ? "" : password, salt);
    }

    /**
     * Verify a candidate against a stored hash.
     *
     * <p>Accepts either format, so a database can hold a mix of old and new
     * hashes while you migrate. Re-hash on successful login.
     */
    public boolean matches(String password, String storedHash) {
        if (storedHash == null || storedHash.isBlank()) {
            return false;
        }
        String candidate = password == null ? "" : password;

        if (storedHash.startsWith("pbkdf2-sha256$")) {
            String[] parts = storedHash.split("\\$");
            if (parts.length != 4) {
                return false;
            }
            int iterations = Integer.parseInt(parts[1]);
            String salt = parts[2];
            String expected = parts[3];
            return constantTimeEquals(pbkdf2(candidate, salt), expected);
        }

        // Legacy unsalted MD5.
        return constantTimeEquals(md5Hex(candidate), storedHash);
    }

    /** True when the stored hash uses the vulnerable scheme. */
    public boolean isLegacyHash(String storedHash) {
        return storedHash != null && !storedHash.startsWith("pbkdf2-sha256$");
    }

    // ---- primitives ----------------------------------------------------

    /**
     * Legacy unsalted MD5 — the verification path for hashes that predate
     * the PBKDF2 migration, and nothing else. Nothing writes a hash with
     * this; {@link #hash(String)} is the only method that produces a stored
     * hash, and it produces PBKDF2.
     */
    public String md5Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] bytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 unavailable", e);
        }
    }

    /**
     * Derive a key with PBKDF2-HMAC-SHA256.
     *
     * <p>The salt is stored base64-encoded, so it round-trips through
     * {@code data.sql} and {@code verify/payloads/hash_passwords.py}
     * unchanged. The derived key is base64-encoded too.
     *
     * <p><strong>Salt handling:</strong> the salt is the base64 <em>text</em>
     * itself, encoded as UTF-8 bytes — not the bytes it decodes to. The
     * Python generator hashes {@code salt_b64.encode()} for the same reason,
     * so the two agree byte for byte.
     */
    private String pbkdf2(String password, String saltBase64) {
        int iterations = 100_000;
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                saltBase64.getBytes(StandardCharsets.UTF_8),
                iterations, 256);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return Base64.getEncoder().encodeToString(factory.generateSecret(spec).getEncoded());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("PBKDF2 unavailable", e);
        }
    }

    private String randomSalt() {
        byte[] salt = new byte[16];
        new java.security.SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }
}
