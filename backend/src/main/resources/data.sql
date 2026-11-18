-- SecureBank Labs — seed data
--
-- Idempotent: re-running on every boot restores a wrecked database.
--
-- LAB 7 (A04 — Cryptographic Failures): the SHIPPED seed stores passwords
-- as UNSALTED MD5. The hashes below must match
-- core/PasswordHasher.md5Hex(...) exactly.
--
-- THE FIX for Lab 7 is to replace this block with salted hashes. Generate
-- a replacement with:
--     python3 verify/payloads/hash_passwords.py
-- The format is:
--     pbkdf2-sha256$<iterations>$<salt-b64>$<hash-b64>
--
-- PasswordHasher.matches() accepts BOTH formats, so the MD5 rows keep
-- working while you migrate. Keep the DO UPDATE so a fixed seed actually
-- replaces the vulnerable rows on the next boot.

INSERT INTO users (id, username, password_hash, email, full_name, role)
VALUES
    (1, 'admin', '21232f297a57a5a743894a0e4a801fc3', 'admin@bank.com', 'Site Administrator', 'admin'),
    (2, 'alice', '482c811da5d5b4bc6d497ffa98491e38', 'alice@bank.com', 'Alice Anderson',     'customer'),
    (3, 'bob',   'd8578edf8458ce06fbc5bb76a58c5ca4', 'bob@bank.com',   'Bob Brown',          'customer'),
    (4, 'carol', '0d107d09f5bbe40cade3de5c71e9e9b7', 'carol@bank.com', 'Carol Clark',        'customer'),
    (5, 'dave',  '4cb9c8a8048fd02294477fcb1a41191a', 'dave@bank.com',  'Dave Davis',         'customer')
ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash;

-- Lab 15 (mass assignment) lets a customer promote themselves, which
-- rewrites the `role` column. Reset it on every boot so a wrecked database
-- heals itself, exactly like the password hashes above.
UPDATE users SET role = 'customer' WHERE username IN ('alice', 'bob', 'carol', 'dave');
UPDATE users SET role = 'admin'   WHERE username = 'admin';

INSERT INTO accounts (id, account_number, sort_code, balance, currency, owner_id)
VALUES
    (1, 'ACC-1001', '20-00-00',  4200.00, 'GBP', 2),
    (2, 'ACC-1002', '20-00-00', 12800.00, 'GBP', 3),
    (3, 'ACC-1003', '20-00-00',  950.00, 'GBP', 4),
    (4, 'ACC-1004', '20-00-00', 30500.00, 'GBP', 5)
ON CONFLICT (account_number) DO NOTHING;

-- Lab 14 (negative transfer) moves money on every probe run, and Lab 13
-- stores a note on every probe run. Both leave the database in a state
-- that is not the seeded state, so the balances are restored on every
-- boot — the same self-healing the password hashes get.
--
-- Only the balances are reset. The transfers are left alone: they are the
-- lab's scratch space, and Lab 13's stored note lives there.
UPDATE accounts SET balance = 4200.00  WHERE id = 1;
UPDATE accounts SET balance = 12800.00 WHERE id = 2;
UPDATE accounts SET balance = 950.00   WHERE id = 3;
UPDATE accounts SET balance = 30500.00 WHERE id = 4;

INSERT INTO transfers (id, from_account_id, to_account_id, amount, note, remark, status, created_by)
VALUES
    (1, 2, 1,  250.00, 'Rent payment',        NULL, 'completed', 3),
    (2, 1, 3,  100.00, 'Utilities',           NULL, 'completed', 2),
    (3, 3, 1,   75.50, 'Groceries',           NULL, 'completed', 4),
    (4, 1, 4,  500.00, 'Savings transfer',    NULL, 'completed', 2),
    (5, 4, 2, 1200.00, 'Invoice 2024-118',    NULL, 'completed', 5)
ON CONFLICT (id) DO NOTHING;

-- The seed inserts explicit ids, which leaves the BIGSERIAL sequences behind.
-- Without this, the first insert the app makes collides with a seeded row
-- ("duplicate key value violates unique constraint transfers_pkey").
SELECT setval(pg_get_serial_sequence('users', 'id'),
              GREATEST((SELECT COALESCE(MAX(id), 0) FROM users), 1));
SELECT setval(pg_get_serial_sequence('accounts', 'id'),
              GREATEST((SELECT COALESCE(MAX(id), 0) FROM accounts), 1));
SELECT setval(pg_get_serial_sequence('transfers', 'id'),
              GREATEST((SELECT COALESCE(MAX(id), 0) FROM transfers), 1));
SELECT setval(pg_get_serial_sequence('password_reset_tokens', 'id'),
              GREATEST((SELECT COALESCE(MAX(id), 0) FROM password_reset_tokens), 1));

-- Reset tokens are stored so Lab 19 (predictable reset token) has state to
-- read. The token format is md5(username + unixTimestamp) — see Lab 19.
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id          BIGSERIAL PRIMARY KEY,
    username    VARCHAR(64)  NOT NULL,
    token       VARCHAR(128) NOT NULL,
    expires_at  TIMESTAMP    NOT NULL,
    used        BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
