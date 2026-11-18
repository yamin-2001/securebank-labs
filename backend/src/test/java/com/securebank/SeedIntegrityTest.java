package com.securebank;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * The seed's integrity.
 *
 * <p>The seeded hashes in {@code data.sql} have to be the hashes of the
 * seeded passwords, or the accounts simply cannot log in — and the symptom
 * (a 401 on a correct password) looks nothing like its cause. This test
 * fails loudly instead.
 *
 * <p>It also pins the shape of the hash format, because Lab 7's fix depends
 * on it: the legacy rows are unsalted MD5, and the fixed rows are
 * {@code pbkdf2-sha256$<iterations>$<salt>$<hash>}.
 */
class SeedIntegrityTest {

    private static final List<String[]> SEED_USERS = List.of(
            new String[] { "1", "admin", "admin" },
            new String[] { "2", "alice", "password123" },
            new String[] { "3", "bob", "qwerty" },
            new String[] { "4", "carol", "letmein" },
            new String[] { "5", "dave", "changeme" });

    private static String seedText() {
        try (var stream = SeedIntegrityTest.class
                .getClassLoader()
                .getResourceAsStream("data.sql")) {
            assertThat(stream).as("data.sql must be on the classpath").isNotNull();
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("could not read data.sql", e);
        }
    }

    private static String md5Hex(String text) {
        try {
            byte[] bytes = MessageDigest.getInstance("MD5")
                    .digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void everySeededHashIsTheHashOfItsPassword() {
        String text = seedText();
        for (String[] user : SEED_USERS) {
            String id = user[0];
            String username = user[1];
            String password = user[2];

            String row = text.lines()
                    .filter(line -> line.strip().startsWith("(" + id + ", '" + username + "',"))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError(
                            "no seed row for " + username + " in data.sql"));

            String expected = md5Hex(password);
            assertThat(row)
                    .as("%s's seeded hash must be md5(%s)", username, password)
                    .contains("'" + expected + "'");
        }
    }

    @Test
    void theLegacyHashFormatIsUnambiguous() {
        // Lab 7's fix swaps MD5 for PBKDF2. The two formats must be
        // distinguishable, or a fixed seed would still be read as legacy.
        String legacy = md5Hex("password123");
        assertThat(legacy).doesNotStartWith("pbkdf2-sha256$");
        assertThat(legacy).hasSize(32);
    }

    @Test
    void theSeedResetsTheLab15RoleChange() {
        // Lab 15 lets a customer promote themselves. The seed has to undo
        // that on every boot, or an exploit in one session leaks into the
        // next.
        String text = seedText();
        assertThat(text).contains(
                "UPDATE users SET role = 'customer' WHERE username IN ('alice', 'bob', 'carol', 'dave')");
        assertThat(text).contains("UPDATE users SET role = 'admin'   WHERE username = 'admin'");
    }

    @Test
    void theSeedRestoresTheLab14Balances() {
        // Lab 14 moves money on every probe run.
        String text = seedText();
        assertThat(text).contains("UPDATE accounts SET balance = 4200.00  WHERE id = 1");
        assertThat(text).contains("UPDATE accounts SET balance = 12800.00 WHERE id = 2");
    }
}
