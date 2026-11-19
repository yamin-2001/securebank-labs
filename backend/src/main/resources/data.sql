-- SecureBank Labs — seed data
--
-- Idempotent: re-running on every boot restores a wrecked database.
--
-- LAB 7 (A04 — Cryptographic Failures): the seed stores passwords as
-- PBKDF2-HMAC-SHA256 with a per-user random salt. The format is:
--     pbkdf2-sha256$<iterations>$<salt-b64>$<hash-b64>
-- and the rows below match core/PasswordHasher.pbkdf2(...) exactly.
-- Generate a replacement with:
--     python3 verify/payloads/hash_passwords.py
--
-- PasswordHasher.matches() accepts BOTH formats, so any remaining MD5 rows
-- keep working while you migrate them. Keep the DO UPDATE so a fixed seed
-- actually replaces the vulnerable rows on the next boot.
--
-- LAB 5 (A02 — Security Misconfiguration): the admin's password has been
-- ROTATED away from the shipped default, so `admin / admin` no longer
-- authenticates against the operations console. It is:
--
--     S3cure-Admin-Passw0rd!

INSERT INTO users (id, username, password_hash, email, full_name, role)
VALUES
    (1, 'admin', 'pbkdf2-sha256$100000$aiqDOnKwABVvMfmWwLhHcg==$BzaM/gbvOPYM0I6+Bv2bPC3ch7kXWXcQNvi/gapDMEM=', 'admin@bank.com', 'Site Administrator', 'admin'),
    (2, 'alice', 'pbkdf2-sha256$100000$XJ9Ii6KTdr4lUI/0TPsCuA==$D0ObSvEvCCYrbuYciro2y9VryTGSKKx4v+btNtJBu+0=', 'alice@bank.com', 'Alice Anderson',     'customer'),
    (3, 'bob',   'pbkdf2-sha256$100000$XAUVTFFdsB9CIEjzAL5B1A==$a8Qb/YzfXULYVJfUjzZS0TNgsmksdpm6Nmxn8VYxOqg=', 'bob@bank.com',   'Bob Brown',          'customer'),
    (4, 'carol', 'pbkdf2-sha256$100000$tEhTL9ce1tQO9HLp7hSJyg==$ax9NtR8NNO9e4ezUruIHd5bLp/k3mn9CF4Q0Pn6zdMI=', 'carol@bank.com', 'Carol Clark',        'customer'),
    (5, 'dave',  'pbkdf2-sha256$100000$Cnsa2bTQMt30J/HAcHDTbQ==$LGZh8OWYBsrXy48j7aIG7C0cKEIj18jzBu266yEJlSU=', 'dave@bank.com',  'Dave Davis',         'customer')
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
