package com.securebank.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.springframework.stereotype.Component;

/**
 * Unsalted MD5 hashing.
 *
 * <p><strong>LAB 7 (A04 — Cryptographic Failures).</strong>
 *
 * <p><strong>FIXED.</strong> This class used to be the storage scheme for
 * every seeded password. It is no longer: passwords are stored as
 * PBKDF2-HMAC-SHA256 with a per-user salt, and the seeded rows in
 * {@code data.sql} have been re-seeded to match.
 *
 * <p>What is left here is the legacy verifier — the piece that lets a
 * database hold a mix of old and new hashes while you migrate the remaining
 * rows, re-hashing each one on its owner's next successful login. It is not
 * a storage strategy and nothing should write a hash with it.
 *
 * <p>Note: fixing Lab 7 does not fix Lab 10 — the SQL comment in the
 * login-bypass payload removes the password predicate entirely, so the
 * injection still works regardless of the hashing algorithm.
 */
@Component
public class Md5Hasher {

    /** Legacy unsalted MD5. Trivially crackable, rainbow-tabled in seconds. */
    public String hex(String input) {
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

    /** Constant-time comparison of an MD5 digest against a plaintext candidate. */
    public boolean matches(String plaintext, String expectedHexDigest) {
        if (expectedHexDigest == null) {
            return false;
        }
        return MessageDigest.isEqual(
                hex(plaintext).getBytes(StandardCharsets.UTF_8),
                expectedHexDigest.getBytes(StandardCharsets.UTF_8));
    }
}
