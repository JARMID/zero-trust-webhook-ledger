-- Reference PostgreSQL 17 Schema: Tenant-Isolated Double-Entry Ledger with Anti-Replay
-- Standalone open-source blueprint (MIT License) by Khalef Abdelmadjid (@JARMID)

CREATE TABLE IF NOT EXISTS ledger_accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    code            TEXT NOT NULL,
    currency        CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    balance_minor   BIGINT NOT NULL DEFAULT 0 CHECK (balance_minor >= 0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, code)
);

CREATE TABLE IF NOT EXISTS payment_receipt_locks (
    tenant_id       UUID NOT NULL,
    tx_ref          TEXT NOT NULL,
    receipt_sha256  CHAR(64) NOT NULL,
    amount_minor    BIGINT NOT NULL CHECK (amount_minor > 0),
    currency        CHAR(3) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, tx_ref),
    UNIQUE (tenant_id, receipt_sha256)
);

CREATE TABLE IF NOT EXISTS ledger_entries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    tx_ref          TEXT NOT NULL,
    account_id      UUID NOT NULL REFERENCES ledger_accounts(id),
    delta_minor     BIGINT NOT NULL CHECK (delta_minor <> 0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Enforce Row Level Security even for table owners
ALTER TABLE ledger_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_accounts FORCE ROW LEVEL SECURITY;

ALTER TABLE payment_receipt_locks ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_receipt_locks FORCE ROW LEVEL SECURITY;

ALTER TABLE ledger_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_entries FORCE ROW LEVEL SECURITY;

-- Strict tenant read isolation (client roles can never mutate ledger balances directly)
DROP POLICY IF EXISTS ledger_accounts_tenant_read ON ledger_accounts;
CREATE POLICY ledger_accounts_tenant_read ON ledger_accounts
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

DROP POLICY IF EXISTS receipt_locks_tenant_read ON payment_receipt_locks;
CREATE POLICY receipt_locks_tenant_read ON payment_receipt_locks
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

DROP POLICY IF EXISTS ledger_entries_tenant_read ON ledger_entries;
CREATE POLICY ledger_entries_tenant_read ON ledger_entries
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- Revoke direct write access from untrusted application roles; route writes through
-- a SECURITY DEFINER stored procedure that acquires FOR UPDATE locks in deterministic UUID order.
REVOKE INSERT, UPDATE, DELETE ON ledger_accounts, payment_receipt_locks, ledger_entries FROM PUBLIC;
