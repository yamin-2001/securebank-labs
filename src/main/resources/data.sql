-- SecureBank Labs — seed data
--
-- Idempotent: re-running on every boot restores a wrecked database.
--
-- Passwords are stored as UNSALTED MD5 on purpose — this is Lab 7
-- (A04 — Cryptographic Failures). The hashes below must match
-- core/Md5Hasher.hex(...) exactly; a JUnit test asserts that.

INSERT INTO users (id, username, password_hash, email, full_name, role)
VALUES
    (1, 'admin', '21232f297a57a5a743894a0e4a801fc3', 'admin@bank.com',   'Site Administrator', 'admin'),
    (2, 'alice', '482c811da5d5b4bc6d497ffa98491e38', 'alice@bank.com',   'Alice Anderson',    'customer'),
    (3, 'bob',   'd8578edf8458ce06fbc5bb76a58c5ca4', 'bob@bank.com',     'Bob Brown',        'customer'),
    (4, 'carol', '35d9b8a73dad4919a46dfed32701f481', 'carol@bank.com',   'Carol Clark',      'customer'),
    (5, 'dave',  '70b9f55c5b2ab6ab9e5a3fed086f1ce7', 'dave@bank.com',    'Dave Davis',       'customer')
ON CONFLICT (username) DO NOTHING;

INSERT INTO accounts (id, account_number, sort_code, balance, currency, owner_id)
VALUES
    (1, 'ACC-1001', '20-00-00',  4200.00, 'GBP', 2),
    (2, 'ACC-1002', '20-00-00', 12800.00, 'GBP', 3),
    (3, 'ACC-1003', '20-00-00',  950.00, 'GBP', 4),
    (4, 'ACC-1004', '20-00-00', 30500.00, 'GBP', 5)
ON CONFLICT (account_number) DO NOTHING;

INSERT INTO transfers (id, from_account_id, to_account_id, amount, note, remark, status, created_by)
VALUES
    (1, 2, 1,  250.00, 'Rent payment',        NULL, 'completed', 3),
    (2, 1, 3,  100.00, 'Utilities',           NULL, 'completed', 2),
    (3, 3, 1,   75.50, 'Groceries',           NULL, 'completed', 4),
    (4, 1, 4,  500.00, 'Savings transfer',    NULL, 'completed', 2),
    (5, 4, 2, 1200.00, 'Invoice 2024-118',    NULL, 'completed', 5)
ON CONFLICT (id) DO NOTHING;

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
