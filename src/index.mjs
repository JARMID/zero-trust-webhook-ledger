import crypto from "node:crypto";

/**
 * Compute a hex-encoded HMAC-SHA256 signature over the exact raw request body.
 * Never re-serialize parsed JSON before signing or verifying.
 */
export function signWebhookPayload(rawBody, secret, timestampSec) {
  if (typeof rawBody !== "string" && !Buffer.isBuffer(rawBody)) {
    throw new TypeError("rawBody must be a UTF-8 string or Buffer");
  }
  if (!secret || typeof secret !== "string") {
    throw new Error("Webhook signing secret is required");
  }
  const bodyStr = Buffer.isBuffer(rawBody) ? rawBody.toString("utf8") : rawBody;
  const canonical = timestampSec !== undefined ? `${timestampSec}.${bodyStr}` : bodyStr;
  return crypto.createHmac("sha256", secret).update(canonical, "utf8").digest("hex");
}

/**
 * Fail-closed constant-time HMAC-SHA256 verification with replay window enforcement.
 */
export function verifyWebhookSignature({
  rawBody,
  signatureHeader,
  secret,
  timestampHeader,
  nowSec = Math.floor(Date.now() / 1000),
  maxSkewSec = 300,
  prefix = "sha256=",
}) {
  if (!secret || !signatureHeader || typeof signatureHeader !== "string") {
    return { ok: false, reason: "missing_secret_or_signature" };
  }
  if (!signatureHeader.startsWith(prefix)) {
    return { ok: false, reason: "invalid_signature_prefix" };
  }

  let tsNum;
  if (timestampHeader !== undefined && timestampHeader !== null && timestampHeader !== "") {
    tsNum = Number(timestampHeader);
    if (!Number.isInteger(tsNum) || tsNum <= 0) {
      return { ok: false, reason: "malformed_timestamp" };
    }
    if (Math.abs(nowSec - tsNum) > maxSkewSec) {
      return { ok: false, reason: "timestamp_outside_window" };
    }
  }

  const providedHex = signatureHeader.slice(prefix.length).trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(providedHex)) {
    return { ok: false, reason: "malformed_hex_digest" };
  }

  const expectedHex = signWebhookPayload(rawBody, secret, tsNum);
  const a = Buffer.from(providedHex, "hex");
  const b = Buffer.from(expectedHex, "hex");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: "signature_mismatch" };
  }
  return { ok: true, reason: "verified" };
}

/**
 * Canonical SHA-256 receipt fingerprint so the same transaction reference or
 * normalized receipt content can never settle twice.
 */
export function computeReceiptFingerprint({ provider, txRef, amountMinor, currency }) {
  const normalized = [
    String(provider || "").trim().toLowerCase(),
    String(txRef || "").trim().toUpperCase(),
    String(amountMinor),
    String(currency || "").trim().toUpperCase(),
  ].join("|");
  return crypto.createHash("sha256").update(normalized, "utf8").digest("hex");
}

/**
 * In-memory reference model of an atomic double-entry ledger with strict
 * tenant isolation, server-locked integer minor units, and HTTP 409 anti-replay.
 */
export class DoubleEntryLedger {
  constructor() {
    this.accounts = new Map();
    this.seenReferences = new Map();
    this.journal = [];
  }

  createAccount({ tenantId, accountId, currency, initialBalanceMinor = 0 }) {
    if (!tenantId || !accountId || !currency) {
      throw new Error("tenantId, accountId, and currency are required");
    }
    if (!Number.isSafeInteger(initialBalanceMinor) || initialBalanceMinor < 0) {
      throw new RangeError("initialBalanceMinor must be a non-negative safe integer");
    }
    const key = `${tenantId}:${accountId}`;
    if (this.accounts.has(key)) {
      throw new Error(`Account already exists: ${key}`);
    }
    this.accounts.set(key, {
      tenantId,
      accountId,
      currency: currency.toUpperCase(),
      balanceMinor: initialBalanceMinor,
    });
  }

  getBalance(tenantId, accountId) {
    const acc = this.accounts.get(`${tenantId}:${accountId}`);
    if (!acc) throw new Error(`Unknown account: ${tenantId}:${accountId}`);
    return acc.balanceMinor;
  }

  /**
   * Atomically post a balanced debit/credit transfer guarded by an idempotency key.
   * Rejects duplicate transaction references with status 409 and rejects negative or
   * cross-tenant / cross-currency transfers before mutating state.
   */
  postTransfer({ tenantId, txRef, debitAccountId, creditAccountId, amountMinor, currency, provider = "webhook" }) {
    if (!tenantId || !txRef) {
      return { ok: false, status: 400, error: "missing_tenant_or_reference" };
    }
    if (!Number.isSafeInteger(amountMinor) || amountMinor <= 0) {
      return { ok: false, status: 400, error: "amount_must_be_positive_integer" };
    }
    if (debitAccountId === creditAccountId) {
      return { ok: false, status: 400, error: "self_transfer_forbidden" };
    }

    const refKey = `${tenantId}:${String(txRef).trim().toUpperCase()}`;
    if (this.seenReferences.has(refKey)) {
      return {
        ok: false,
        status: 409,
        error: "duplicate_transaction_reference",
        originalEntryId: this.seenReferences.get(refKey),
      };
    }

    const debit = this.accounts.get(`${tenantId}:${debitAccountId}`);
    const credit = this.accounts.get(`${tenantId}:${creditAccountId}`);
    if (!debit || !credit) {
      return { ok: false, status: 404, error: "account_not_found_in_tenant" };
    }
    const normCurrency = String(currency || "").trim().toUpperCase();
    if (debit.currency !== normCurrency || credit.currency !== normCurrency) {
      return { ok: false, status: 422, error: "currency_mismatch" };
    }
    if (debit.balanceMinor < amountMinor) {
      return { ok: false, status: 422, error: "insufficient_funds" };
    }

    // Atomic state update (mirrors PostgreSQL SELECT ... FOR UPDATE transaction)
    debit.balanceMinor -= amountMinor;
    credit.balanceMinor += amountMinor;

    const entryId = `je_${this.journal.length + 1}`;
    const fingerprint = computeReceiptFingerprint({ provider, txRef, amountMinor, currency: normCurrency });
    const entry = Object.freeze({
      entryId,
      tenantId,
      txRef: String(txRef).trim().toUpperCase(),
      fingerprint,
      currency: normCurrency,
      legs: Object.freeze([
        Object.freeze({ accountId: debitAccountId, direction: "DEBIT", amountMinor: -amountMinor }),
        Object.freeze({ accountId: creditAccountId, direction: "CREDIT", amountMinor: amountMinor }),
      ]),
      createdAt: new Date().toISOString(),
    });

    this.seenReferences.set(refKey, entryId);
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
