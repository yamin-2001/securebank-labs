package com.securebank;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.junit.jupiter.api.Test;

/**
 * The seed's integrity.
 *
 * <p>The seeded hashes in {@code data.sql} have to be the hashes of the
 * seeded passwords, or the accounts simply cannot log in — and the symptom
 * (a 401 on a correct password) looks nothing like its cause. This test
 * fails loudly instead.
 *
 * <p><strong>LAB 7 (FIXED):</strong> the seeded rows are salted
 * PBKDF2-HMAC-SHA256, so this test derives the hash the same way
 * {@code PasswordHasher} does and checks the stored value against it.
 * The salt is the base64 <em>text</em>, encoded as UTF-8 bytes — not the
 * bytes it decodes to — which is what {@code PBEKeySpec} does with a char
 * array.
 */
class SeedIntegrityTest {

    private static final List<String[]> SEED_USERS = List.of(
            // LAB 5 (A02 — Security Misconfiguration): the admin's password has
            // been rotated away from the shipped default, so the operations
            // console no longer accepts `admin / admin`. The other accounts
            // keep their documented passwords.
            new String[] { "1", "admin", "S3cure-Admin-Passw0rd!" },
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

    /** Derive the hash the way PasswordHasher.pbkdf2() does. */
    private static String pbkdf2Hex(String password, String saltBase64, int iterations) {
        try {
            PBEKeySpec spec = new PBEKeySpec(
                    password.toCharArray(),
                    saltBase64.getBytes(StandardCharsets.UTF_8),
                    iterations, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return Base64.getEncoder().encodeToString(factory.generateSecret(spec).getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Pull the stored hash out of a seed row. */
    private static String storedHash(String row) {
        int start = row.indexOf("', '");
        // The hash is the third comma-separated field, after id and username.
        int firstComma = row.indexOf(',');
        int secondComma = row.indexOf(',', firstComma + 1);
        int thirdComma = row.indexOf(',', secondComma + 1);
        String field = row.substring(secondComma + 1, thirdComma).trim();
        return field.startsWith("'") && field.endsWith("'")
                ? field.substring(1, field.length() - 1)
                : field;
    }

    @Test
    void everySeededHashIsTheHashOfItsPassword() {
        List<String> rows = userRows();
        assertThat(rows).hasSize(SEED_USERS.size());

        for (int i = 0; i < SEED_USERS.size(); i++) {
            String[] user = SEED_USERS.get(i);
            String username = user[1];
            String password = user[2];

            String stored = storedHash(rows.get(i));
            assertThat(stored)
                    .as("%s's seeded hash must use the PBKDF2 format", username)
                    .startsWith("pbkdf2-sha256$");

            String[] parts = stored.split("\\$");
            assertThat(parts).as("%s's seeded hash must have four parts", username).hasSize(4);
            int iterations = Integer.parseInt(parts[1]);
            String salt = parts[2];
            String expected = pbkdf2Hex(password, salt, iterations);

            assertThat(stored)
                    .as("%s's seeded hash must be pbkdf2(%s, its own salt)", username, password)
                    .isEqualTo("pbkdf2-sha256$" + iterations + "$" + salt + "$" + expected);
        }
    }

    /** The user rows in data.sql — the ones that carry a password hash. */
    private static List<String> userRows() {
        String text = seedText();
        return SEED_USERS.stream()
                .map(user -> text.lines()
                        .filter(line -> line.strip().startsWith("(" + user[0] + ", '" + user[1] + "',"))
                        .findFirst()
                        .orElseThrow(() -> new AssertionError(
                                "no seed row for " + user[1] + " in data.sql")))
                .toList();
    }

    @Test
    void everySeededHashHasItsOwnSalt() {
        // An unsalted scheme is Lab 7's bug. Two users with the same password
        // must not produce the same stored hash.
        List<String> salts = userRows().stream()
                .map(SeedIntegrityTest::storedHash)
                .map(hash -> hash.split("\\$")[2])
                .toList();
        assertThat(salts).hasSize(5);
        assertThat(salts).doesNotHaveDuplicates();
    }

    @Test
    void noSeededRowUsesUnsaltedMd5() {
        // The legacy MD5 format is still readable, so a stray MD5 row would
        // keep working — and would keep being crackable.
        for (String row : userRows()) {
            String stored = storedHash(row);
            assertThat(stored)
                    .as("every seeded row must use PBKDF2, found: %s", stored)
                    .startsWith("pbkdf2-sha256$");
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
