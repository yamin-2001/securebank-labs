-- SecureBank Labs — schema
--
-- Owned by schema.sql (spring.jpa.hibernate.ddl-auto=validate only checks it).
-- Every statement is idempotent so the seed is self-healing on each boot.

CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL PRIMARY KEY,
    username        VARCHAR(64)  NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    email           VARCHAR(255) NOT NULL,
    full_name       VARCHAR(255),
    role            VARCHAR(32)  NOT NULL DEFAULT 'customer',
    created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS accounts (
    id              BIGSERIAL PRIMARY KEY,
    account_number  VARCHAR(32)  NOT NULL UNIQUE,
    sort_code       VARCHAR(16)  NOT NULL,
    balance         NUMERIC(15,2) NOT NULL DEFAULT 0,
    currency        VARCHAR(8)   NOT NULL DEFAULT 'GBP',
    owner_id        BIGINT       NOT NULL REFERENCES users (id),
    created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transfers (
    id              BIGSERIAL PRIMARY KEY,
    from_account_id BIGINT       NOT NULL REFERENCES accounts (id),
    to_account_id   BIGINT       NOT NULL REFERENCES accounts (id),
    amount          NUMERIC(15,2) NOT NULL,
    note            TEXT,
    remark          TEXT,
    status          VARCHAR(32)  NOT NULL DEFAULT 'completed',
    created_by      BIGINT       REFERENCES users (id),
    created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_accounts_owner ON accounts (owner_id);
CREATE INDEX IF NOT EXISTS idx_transfers_from ON transfers (from_account_id);
CREATE INDEX IF NOT EXISTS idx_transfers_to   ON transfers (to_account_id);
CREATE INDEX IF NOT EXISTS idx_transfers_note ON transfers (note);
