import crypto from "node:crypto";

function compositeKey(...parts) {
  return JSON.stringify(parts.map((p) => String(p)));
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

/**
 * Compute a hex-encoded HMAC-SHA256 signature over the exact raw request bytes.
 * Hashes raw Buffer bytes directly without lossy UTF-8 re-encoding.
 */
export function signWebhookPayload(rawBody, secret, timestampSec) {
  if (typeof rawBody !== "string" && !Buffer.isBuffer(rawBody)) {
    throw new TypeError("rawBody must be a UTF-8 string or Buffer");
  }
  if (!isNonEmptyString(secret)) {
    throw new Error("Webhook signing secret is required");
  }
  const hmac = crypto.createHmac("sha256", secret);
  if (timestampSec !== undefined) {
    hmac.update(`${timestampSec}.`, "utf8");
  }
  if (Buffer.isBuffer(rawBody)) {
    hmac.update(rawBody);
  } else {
    hmac.update(rawBody, "utf8");
  }
  return hmac.digest("hex");
}

/**
 * Fail-closed constant-time HMAC-SHA256 verification with mandatory replay window enforcement.
 */
export function verifyWebhookSignature({
  rawBody,
  signatureHeader,
  secret,
  timestampHeader,
  requireTimestamp = true,
  nowSec = Math.floor(Date.now() / 1000),
  maxSkewSec = 300,
  prefix = "sha256=",
}) {
  if (typeof rawBody !== "string" && !Buffer.isBuffer(rawBody)) {
    return { ok: false, reason: "invalid_raw_body" };
  }
  if (!isNonEmptyString(secret) || typeof signatureHeader !== "string" || signatureHeader.length === 0) {
    return { ok: false, reason: "missing_secret_or_signature" };
  }
  if (typeof prefix !== "string" || !signatureHeader.startsWith(prefix)) {
    return { ok: false, reason: "invalid_signature_prefix" };
  }
  if (!Number.isSafeInteger(nowSec) || nowSec <= 0 || !Number.isFinite(maxSkewSec) || maxSkewSec < 0) {
    return { ok: false, reason: "invalid_clock_window_config" };
  }

  let tsNum;
  const hasTimestamp = timestampHeader !== undefined && timestampHeader !== null && timestampHeader !== "";
  if (requireTimestamp && !hasTimestamp) {
    return { ok: false, reason: "missing_timestamp" };
  }
  if (hasTimestamp) {
    const tsStr = String(timestampHeader);
    if (!/^[1-9]\d{0,14}$/.test(tsStr)) {
      return { ok: false, reason: "malformed_timestamp" };
    }
    tsNum = Number(tsStr);
    if (!Number.isSafeInteger(tsNum) || tsNum <= 0) {
      return { ok: false, reason: "malformed_timestamp" };
    }
    if (Math.abs(nowSec - tsNum) > maxSkewSec) {
      return { ok: false, reason: "timestamp_outside_window" };
    }
  }

  // Strictly forbid leading/trailing whitespace around the hex digest
  const providedRaw = signatureHeader.slice(prefix.length);
  if (!/^[0-9a-fA-F]{64}$/.test(providedRaw)) {
    return { ok: false, reason: "malformed_hex_digest" };
  }
  const providedHex = providedRaw.toLowerCase();

  const expectedHex = signWebhookPayload(rawBody, secret, tsNum);
  const a = Buffer.from(providedHex, "hex");
  const b = Buffer.from(expectedHex, "hex");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: "signature_mismatch" };
  }
  return { ok: true, reason: "verified" };
}

/**
 * Canonical SHA-256 receipt fingerprint using delimiter-safe JSON array encoding
 * so field characters (such as pipes or colons) can never cause cross-field collisions.
 */
export function computeReceiptFingerprint({ provider, txRef, amountMinor, currency }) {
  if (!Number.isSafeInteger(amountMinor) || amountMinor <= 0) {
    throw new RangeError("amountMinor must be a positive safe integer");
  }
  const canonical = JSON.stringify([
    String(provider || "").trim().toLowerCase(),
    String(txRef || "").trim().toUpperCase(),
    String(amountMinor),
    String(currency || "").trim().toUpperCase(),
  ]);
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

/**
 * In-memory reference model of an atomic double-entry ledger with strict
 * tenant isolation, overflow protection, server-locked integer minor units,
 * and HTTP 409 anti-replay on both txRef and canonical receipt fingerprint.
 */
export class DoubleEntryLedger {
  constructor() {
    this.accounts = new Map();
    this.seenReferences = new Map();
    this.seenFingerprints = new Map();
    this.journal = [];
  }

  createAccount({ tenantId, accountId, currency, initialBalanceMinor = 0 }) {
    if (!isNonEmptyString(tenantId) || !isNonEmptyString(accountId) || !isNonEmptyString(currency)) {
      throw new Error("tenantId, accountId, and currency must be non-empty strings");
    }
    const normCurrency = currency.trim().toUpperCase();
    if (!/^[A-Z]{3}$/.test(normCurrency)) {
      throw new RangeError("currency must be a 3-letter ISO code");
    }
    if (!Number.isSafeInteger(initialBalanceMinor) || initialBalanceMinor < 0) {
      throw new RangeError("initialBalanceMinor must be a non-negative safe integer");
    }
    const key = compositeKey(tenantId.trim(), accountId.trim());
    if (this.accounts.has(key)) {
      throw new Error(`Account already exists for tenant ${tenantId}`);
    }
    this.accounts.set(key, {
      tenantId: tenantId.trim(),
      accountId: accountId.trim(),
      currency: normCurrency,
      balanceMinor: initialBalanceMinor,
    });
  }

  getBalance(tenantId, accountId) {
    if (!isNonEmptyString(tenantId) || !isNonEmptyString(accountId)) {
      throw new Error("tenantId and accountId are required");
    }
    const acc = this.accounts.get(compositeKey(tenantId.trim(), accountId.trim()));
    if (!acc) throw new Error("Unknown account for tenant");
    return acc.balanceMinor;
  }

  /**
   * Atomically post a balanced debit/credit transfer guarded by tenant-scoped
   * idempotency keys and receipt fingerprint uniqueness.
   */
  postTransfer({
    tenantId,
    txRef,
    debitAccountId,
    creditAccountId,
    amountMinor,
    currency,
    provider = "webhook",
    receiptFingerprint,
  }) {
    if (!isNonEmptyString(tenantId) || !isNonEmptyString(txRef)) {
      return { ok: false, status: 400, error: "missing_tenant_or_reference" };
    }
    if (!isNonEmptyString(debitAccountId) || !isNonEmptyString(creditAccountId)) {
      return { ok: false, status: 400, error: "missing_account_ids" };
    }
    if (!Number.isSafeInteger(amountMinor) || amountMinor <= 0) {
      return { ok: false, status: 400, error: "amount_must_be_positive_integer" };
    }

    const normTenant = tenantId.trim();
    const normDebitId = debitAccountId.trim();
    const normCreditId = creditAccountId.trim();
    const normTxRef = txRef.trim().toUpperCase();
    const normCurrency = String(currency || "").trim().toUpperCase();

    if (normDebitId === normCreditId) {
      return { ok: false, status: 400, error: "self_transfer_forbidden" };
    }

    const refKey = compositeKey(normTenant, normTxRef);
    if (this.seenReferences.has(refKey)) {
      return {
        ok: false,
        status: 409,
        error: "duplicate_transaction_reference",
        originalEntryId: this.seenReferences.get(refKey),
      };
    }

    let fingerprint;
    if (receiptFingerprint !== undefined) {
      if (typeof receiptFingerprint !== "string" || !/^[0-9a-fA-F]{64}$/.test(receiptFingerprint)) {
        return { ok: false, status: 400, error: "invalid_receipt_fingerprint" };
      }
      fingerprint = receiptFingerprint.toLowerCase();
    } else {
      fingerprint = computeReceiptFingerprint({
        provider,
        txRef: normTxRef,
        amountMinor,
        currency: normCurrency,
      });
    }
    const fpKey = compositeKey(normTenant, fingerprint);
    if (this.seenFingerprints.has(fpKey)) {
      return {
        ok: false,
        status: 409,
        error: "duplicate_receipt_fingerprint",
        originalEntryId: this.seenFingerprints.get(fpKey),
      };
    }

    const debit = this.accounts.get(compositeKey(normTenant, normDebitId));
    const credit = this.accounts.get(compositeKey(normTenant, normCreditId));
    if (!debit || !credit) {
      return { ok: false, status: 404, error: "account_not_found_in_tenant" };
    }
    if (debit.currency !== normCurrency || credit.currency !== normCurrency) {
      return { ok: false, status: 422, error: "currency_mismatch" };
    }
    if (debit.balanceMinor < amountMinor) {
      return { ok: false, status: 422, error: "insufficient_funds" };
    }
    if (credit.balanceMinor > Number.MAX_SAFE_INTEGER - amountMinor) {
      return { ok: false, status: 422, error: "balance_overflow" };
    }

    // Atomic state update (mirrors PostgreSQL SELECT ... FOR UPDATE transaction)
    debit.balanceMinor -= amountMinor;
    credit.balanceMinor += amountMinor;

    const entryId = `je_${this.journal.length + 1}`;
    const entry = Object.freeze({
      entryId,
      tenantId: normTenant,
      txRef: normTxRef,
      fingerprint,
      currency: normCurrency,
      legs: Object.freeze([
        Object.freeze({ accountId: normDebitId, direction: "DEBIT", amountMinor: -amountMinor }),
        Object.freeze({ accountId: normCreditId, direction: "CREDIT", amountMinor: amountMinor }),
      ]),
      createdAt: new Date().toISOString(),
    });

    this.seenReferences.set(refKey, entryId);
    this.seenFingerprints.set(fpKey, entryId);
    this.journal.push(entry);
    return { ok: true, status: 201, entry };
  }

  /**
   * Verify the double-entry invariant: sum of all legs in every journal entry equals 0.
   */
  verifyTrialBalance() {
    for (const entry of this.journal) {
      const sum = entry.legs.reduce((acc, leg) => acc + leg.amountMinor, 0);
      if (sum !== 0) {
        return { balanced: false, failingEntryId: entry.entryId, netSum: sum };
      }
    }
    return { balanced: true, entryCount: this.journal.length };
  }
}
