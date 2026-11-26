import test from "node:test";
import assert from "node:assert/strict";
import {
  signWebhookPayload,
  verifyWebhookSignature,
  computeReceiptFingerprint,
  DoubleEntryLedger,
} from "../src/index.mjs";

test("verifyWebhookSignature accepts valid timestamped HMAC-SHA256 payload", () => {
  const secret = "whsec_live_9f8e7d6c5b4a";
  const rawBody = JSON.stringify({ tx_ref: "PAY-2026-0001", amount_minor: 150000 });
  const nowSec = 1795650000;
  const sig = `sha256=${signWebhookPayload(rawBody, secret, nowSec)}`;

  const res = verifyWebhookSignature({
    rawBody,
    signatureHeader: sig,
    secret,
    timestampHeader: String(nowSec),
    nowSec: nowSec + 12,
  });
  assert.equal(res.ok, true);
  assert.equal(res.reason, "verified");
});

test("verifyWebhookSignature fails closed on tampered body, wrong secret, stale timestamp, or malformed hex", () => {
  const secret = "whsec_live_9f8e7d6c5b4a";
  const rawBody = JSON.stringify({ tx_ref: "PAY-2026-0001", amount_minor: 150000 });
  const nowSec = 1795650000;
  const sig = `sha256=${signWebhookPayload(rawBody, secret, nowSec)}`;

  const tampered = verifyWebhookSignature({
    rawBody: JSON.stringify({ tx_ref: "PAY-2026-0001", amount_minor: 1500000 }),
    signatureHeader: sig,
    secret,
    timestampHeader: String(nowSec),
    nowSec,
  });
  assert.equal(tampered.ok, false);
  assert.equal(tampered.reason, "signature_mismatch");

  const stale = verifyWebhookSignature({
    rawBody,
    signatureHeader: sig,
    secret,
    timestampHeader: String(nowSec - 600),
    nowSec,
    maxSkewSec: 300,
  });
  assert.equal(stale.ok, false);
  assert.equal(stale.reason, "timestamp_outside_window");

  const missingSecret = verifyWebhookSignature({ rawBody, signatureHeader: sig, secret: "" });
  assert.equal(missingSecret.ok, false);

  const badHex = verifyWebhookSignature({ rawBody, signatureHeader: "sha256=not-hex", secret });
  assert.equal(badHex.ok, false);
  assert.equal(badHex.reason, "malformed_hex_digest");
});

test("DoubleEntryLedger settles once, rejects replay with 409, and preserves zero-sum trial balance", () => {
  const ledger = new DoubleEntryLedger();
  ledger.createAccount({ tenantId: "t_alpha", accountId: "clearing", currency: "DZD", initialBalanceMinor: 500000 });
  ledger.createAccount({ tenantId: "t_alpha", accountId: "merchant", currency: "DZD", initialBalanceMinor: 0 });
  ledger.createAccount({ tenantId: "t_beta", accountId: "merchant", currency: "DZD", initialBalanceMinor: 0 });

  const first = ledger.postTransfer({
    tenantId: "t_alpha",
    txRef: "BM-882419",
    debitAccountId: "clearing",
    creditAccountId: "merchant",
    amountMinor: 150000,
    currency: "DZD",
  });
  assert.equal(first.ok, true);
  assert.equal(first.status, 201);
  assert.equal(ledger.getBalance("t_alpha", "clearing"), 350000);
  assert.equal(ledger.getBalance("t_alpha", "merchant"), 150000);

  // Replay attack with whitespace and lower-case variant of same reference
  const replay = ledger.postTransfer({
    tenantId: "t_alpha",
    txRef: "  bm-882419 ",
    debitAccountId: "clearing",
    creditAccountId: "merchant",
    amountMinor: 150000,
    currency: "DZD",
  });
  assert.equal(replay.ok, false);
  assert.equal(replay.status, 409);
  assert.equal(replay.error, "duplicate_transaction_reference");
  assert.equal(ledger.getBalance("t_alpha", "merchant"), 150000);

  // Cross-tenant isolation check
  const crossTenant = ledger.postTransfer({
    tenantId: "t_beta",
    txRef: "BM-999999",
    debitAccountId: "clearing",
    creditAccountId: "merchant",
    amountMinor: 1000,
    currency: "DZD",
  });
  assert.equal(crossTenant.ok, false);
  assert.equal(crossTenant.status, 404);

  // Overdraft and negative amounts rejected
  const overdraft = ledger.postTransfer({
    tenantId: "t_alpha",
    txRef: "BM-OVERDRAFT",
    debitAccountId: "clearing",
    creditAccountId: "merchant",
    amountMinor: 9999999,
    currency: "DZD",
  });
  assert.equal(overdraft.status, 422);

  const negative = ledger.postTransfer({
    tenantId: "t_alpha",
    txRef: "BM-NEG",
    debitAccountId: "clearing",
    creditAccountId: "merchant",
    amountMinor: -500,
    currency: "DZD",
  });
  assert.equal(negative.status, 400);

  const balanceCheck = ledger.verifyTrialBalance();
  assert.equal(balanceCheck.balanced, true);
  assert.equal(balanceCheck.entryCount, 1);
});

test("computeReceiptFingerprint is deterministic across casing and whitespace", () => {
  const h1 = computeReceiptFingerprint({ provider: "BaridiMob", txRef: "bm-1029", amountMinor: 4500, currency: "dzd" });
  const h2 = computeReceiptFingerprint({ provider: " baridimob ", txRef: " BM-1029 ", amountMinor: 4500, currency: "DZD" });
  assert.equal(h1, h2);
  assert.equal(h1.length, 64);
});
