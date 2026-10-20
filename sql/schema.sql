-- emv-auth-host schema. All money is integer minor units (pence); never REAL.
-- Full PANs are never stored: cards are keyed by HMAC-SHA256(token key, PAN).

CREATE TABLE IF NOT EXISTS accounts (
    account_id      INTEGER PRIMARY KEY,
    currency        TEXT    NOT NULL CHECK (length(currency) = 3),   -- ISO 4217 numeric, e.g. 826
    opening_minor   INTEGER NOT NULL CHECK (opening_minor >= 0),
    available_minor INTEGER NOT NULL CHECK (available_minor >= 0)    -- the database itself refuses an overdraft
);

CREATE TABLE IF NOT EXISTS cards (
    pan_token           BLOB    PRIMARY KEY CHECK (length(pan_token) = 32),
    pan_last4           TEXT    NOT NULL CHECK (length(pan_last4) = 4),
    psn                 TEXT    NOT NULL DEFAULT '00' CHECK (length(psn) = 2),
    expiry_yymm         TEXT    NOT NULL CHECK (length(expiry_yymm) = 4),
    status              TEXT    NOT NULL CHECK (status IN ('ACTIVE', 'BLOCKED', 'LOST')),
    account_id          INTEGER NOT NULL REFERENCES accounts (account_id),
    last_atc            INTEGER NOT NULL DEFAULT -1,                 -- highest ATC with a valid ARQC
    per_txn_limit_minor INTEGER NOT NULL CHECK (per_txn_limit_minor > 0)
) WITHOUT ROWID;

-- One row per 0200 that got far enough to have a terminal/STAN/date key.
CREATE TABLE IF NOT EXISTS authorizations (
    auth_id       INTEGER PRIMARY KEY,
    terminal_id   TEXT    NOT NULL,
    stan          TEXT    NOT NULL,
    tx_datetime   TEXT    NOT NULL,                                  -- DE7 MMDDhhmmss
    request_hash  BLOB    NOT NULL,                                  -- SHA-256 of the request bytes
    pan_token     BLOB,
    pan_last4     TEXT,
    account_id    INTEGER REFERENCES accounts (account_id),
    amount_minor  INTEGER NOT NULL CHECK (amount_minor >= 0),
    currency      TEXT    NOT NULL,
    atc           INTEGER,
    response_code TEXT    NOT NULL,
    reason        TEXT    NOT NULL,
    auth_code     TEXT,
    rrn           TEXT    NOT NULL UNIQUE,
    state         TEXT    NOT NULL CHECK (state IN ('APPROVED', 'DECLINED', 'REVERSED')),
    response      BLOB    NOT NULL,                                  -- exact 0210 bytes, replayed for duplicates
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (terminal_id, stan, tx_datetime),                         -- the idempotency key
    CHECK ((state = 'DECLINED') = (response_code <> '00'))
);

CREATE INDEX IF NOT EXISTS authorizations_by_account ON authorizations (account_id, state);

CREATE TABLE IF NOT EXISTS reversals (
    reversal_id   INTEGER PRIMARY KEY,
    terminal_id   TEXT    NOT NULL,
    stan          TEXT    NOT NULL,
    tx_datetime   TEXT    NOT NULL,
    request_hash  BLOB    NOT NULL,
    orig_auth_id  INTEGER REFERENCES authorizations (auth_id),       -- NULL: original never reached us
    response_code TEXT    NOT NULL,
    reason        TEXT    NOT NULL,
    response      BLOB    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (terminal_id, stan, tx_datetime)
);

-- Reconciliation: every account's balance must equal opening minus live approvals.
CREATE VIEW IF NOT EXISTS recon AS
SELECT a.account_id,
       a.opening_minor - COALESCE(SUM(CASE WHEN z.state = 'APPROVED' THEN z.amount_minor END), 0) AS expected_minor,
       a.available_minor AS actual_minor
FROM accounts a
LEFT JOIN authorizations z ON z.account_id = a.account_id
GROUP BY a.account_id;
