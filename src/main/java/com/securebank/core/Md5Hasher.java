package com.securebank.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.springframework.stereotype.Component;

/**
 * Unsalted MD5 hashing.
 *
 * <p><strong>LAB 7 (A04 — Cryptographic Failures).</strong> This class exists
 * because the lab needs real MD5 hashes to crack, and real unsalted MD5
 * password storage to attack. It is NOT a real password hashing strategy.
 *
 * <p><strong>FIX:</strong> replace every use of this class with
 * {@code BCryptPasswordEncoder} (or Argon2). The seeded rows in
 * {@code data.sql} carry MD5 hashes; the fix must re-seed or migrate them.
 * Note that fixing Lab 7 does not fix Lab 10 — the SQL comment in the
 * login-bypass payload removes the password predicate entirely, so the
 * injection still works regardless of the hashing algorithm.
 */
@Component
public class Md5Hasher {

    /** LAB 7: unsalted MD5. Trivially crackable, rainbow-tabled in seconds. */
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
