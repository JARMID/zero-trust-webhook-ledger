-- Reference PostgreSQL 17 Schema: Tenant-Isolated Double-Entry Ledger with Anti-Replay
-- Standalone open-source blueprint (MIT License) by Khalef Abdelmadjid (@JARMID)

CREATE TABLE IF NOT EXISTS ledger_accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    code            TEXT NOT NULL,
    currency        CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    balance_minor   BIGINT NOT NULL DEFAULT 0 CHECK (balance_minor >= 0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, code),
    UNIQUE (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS payment_receipt_locks (
    tenant_id       UUID NOT NULL,
    tx_ref          TEXT NOT NULL,
    receipt_sha256  CHAR(64) NOT NULL CHECK (receipt_sha256 ~ '^[0-9a-f]{64}$'),
    amount_minor    BIGINT NOT NULL CHECK (amount_minor > 0),
    currency        CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, tx_ref),
    UNIQUE (tenant_id, receipt_sha256)
);

CREATE TABLE IF NOT EXISTS ledger_entries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    tx_ref          TEXT NOT NULL,
    account_id      UUID NOT NULL,
    delta_minor     BIGINT NOT NULL CHECK (delta_minor <> 0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_ledger_entries_account_tenant
        FOREIGN KEY (tenant_id, account_id) REFERENCES ledger_accounts(tenant_id, id),
    CONSTRAINT fk_ledger_entries_receipt_lock
        FOREIGN KEY (tenant_id, tx_ref) REFERENCES payment_receipt_locks(tenant_id, tx_ref)
);

CREATE INDEX IF NOT EXISTS idx_ledger_entries_tenant_tx_ref
    ON ledger_entries (tenant_id, tx_ref);

-- Enforce Row Level Security even for table owners
ALTER TABLE ledger_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_accounts FORCE ROW LEVEL SECURITY;

ALTER TABLE payment_receipt_locks ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_receipt_locks FORCE ROW LEVEL SECURITY;

ALTER TABLE ledger_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_entries FORCE ROW LEVEL SECURITY;

-- Strict tenant read isolation using NULLIF so an empty GUC fails closed cleanly
DROP POLICY IF EXISTS ledger_accounts_tenant_read ON ledger_accounts;
CREATE POLICY ledger_accounts_tenant_read ON ledger_accounts
    FOR SELECT
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS receipt_locks_tenant_read ON payment_receipt_locks;
CREATE POLICY receipt_locks_tenant_read ON payment_receipt_locks
    FOR SELECT
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS ledger_entries_tenant_read ON ledger_entries;
CREATE POLICY ledger_entries_tenant_read ON ledger_entries
    FOR SELECT
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- Revoke all direct write and truncate privileges from untrusted application roles
REVOKE INSERT, UPDATE, DELETE, TRUNCATE
    ON ledger_accounts, payment_receipt_locks, ledger_entries
    FROM PUBLIC;

-- Atomic SECURITY DEFINER transfer entrypoint with deterministic UUID lock ordering
-- to eliminate deadlocks while enforcing tenant isolation, anti-replay, and zero-sum legs.
CREATE OR REPLACE FUNCTION post_double_entry_transfer(
    p_tenant_id         UUID,
    p_tx_ref            TEXT,
    p_receipt_sha256    CHAR(64),
    p_debit_account_id  UUID,
    p_credit_account_id UUID,
    p_amount_minor      BIGINT,
    p_currency          CHAR(3)
) RETURNS TABLE (status_code INT, message TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_debit   ledger_accounts%ROWTYPE;
    v_credit  ledger_accounts%ROWTYPE;
    v_locked  INT := 0;
BEGIN
    IF p_amount_minor IS NULL OR p_amount_minor <= 0 THEN
        RETURN QUERY SELECT 400, 'amount_must_be_positive_integer';
        RETURN;
    END IF;

    IF p_debit_account_id = p_credit_account_id THEN
        RETURN QUERY SELECT 400, 'self_transfer_forbidden';
        RETURN;
    END IF;

    -- Acquire anti-replay lock first inside the transaction
    BEGIN
        INSERT INTO payment_receipt_locks (tenant_id, tx_ref, receipt_sha256, amount_minor, currency)
        VALUES (p_tenant_id, upper(btrim(p_tx_ref)), lower(p_receipt_sha256), p_amount_minor, upper(btrim(p_currency)));
    EXCEPTION WHEN unique_violation THEN
        RETURN QUERY SELECT 409, 'duplicate_transaction_or_receipt';
        RETURN;
    END;

    -- Lock both accounts in deterministic UUID order to prevent deadlocks
    PERFORM id
      FROM ledger_accounts
     WHERE tenant_id = p_tenant_id
       AND id IN (p_debit_account_id, p_credit_account_id)
     ORDER BY id ASC
     FOR UPDATE;

    GET DIAGNOSTICS v_locked = ROW_COUNT;
    IF v_locked <> 2 THEN
        RAISE EXCEPTION 'account_not_found_in_tenant';
    END IF;

    SELECT * INTO v_debit
      FROM ledger_accounts
     WHERE tenant_id = p_tenant_id AND id = p_debit_account_id;

    SELECT * INTO v_credit
      FROM ledger_accounts
     WHERE tenant_id = p_tenant_id AND id = p_credit_account_id;

    IF v_debit.currency <> upper(btrim(p_currency)) OR v_credit.currency <> upper(btrim(p_currency)) THEN
        RAISE EXCEPTION 'currency_mismatch';
    END IF;

    IF v_debit.balance_minor < p_amount_minor THEN
        RAISE EXCEPTION 'insufficient_funds';
    END IF;

    UPDATE ledger_accounts
       SET balance_minor = balance_minor - p_amount_minor
     WHERE tenant_id = p_tenant_id AND id = p_debit_account_id;

    UPDATE ledger_accounts
       SET balance_minor = balance_minor + p_amount_minor
     WHERE tenant_id = p_tenant_id AND id = p_credit_account_id;

    INSERT INTO ledger_entries (tenant_id, tx_ref, account_id, delta_minor)
    VALUES
        (p_tenant_id, upper(btrim(p_tx_ref)), p_debit_account_id, -p_amount_minor),
        (p_tenant_id, upper(btrim(p_tx_ref)), p_credit_account_id, p_amount_minor);

    RETURN QUERY SELECT 201, 'settled';
END;
$$;

REVOKE ALL ON FUNCTION post_double_entry_transfer(UUID, TEXT, CHAR, UUID, UUID, BIGINT, CHAR) FROM PUBLIC;
