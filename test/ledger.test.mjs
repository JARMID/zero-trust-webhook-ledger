import test from "node:test";
import assert from "node:assert/strict";
import {
  signWebhookPayload,
  verifyWebhookSignature,
  computeReceiptFingerprint,
  DoubleEntryLedger,
} from "../src/index.mjs";

const TEST_SECRET = "test_webhook_secret_fixture_9f8e7d6c5b4a";

test("verifyWebhookSignature accepts valid timestamped UTF-8 string and raw Buffer payloads", () => {
  const rawBody = JSON.stringify({ tx_ref: "PAY-2026-0001", amount_minor: 150000 });
  const nowSec = 1795650000;
  const sig = `sha256=${signWebhookPayload(rawBody, TEST_SECRET, nowSec)}`;

  const res = verifyWebhookSignature({
    rawBody,
    signatureHeader: sig,
    secret: TEST_SECRET,
    timestampHeader: String(nowSec),
    nowSec: nowSec + 12,
  });
  assert.equal(res.ok, true);
  assert.equal(res.reason, "verified");

  // Raw non-UTF8 binary Buffer must be signed and verified without UTF-8 replacement corruption
  const rawBinary = Buffer.from([0xff, 0xfe, 0x00, 0x80, 0x7b, 0x7d]);
  const binSig = `sha256=${signWebhookPayload(rawBinary, TEST_SECRET, nowSec)}`;
  const binRes = verifyWebhookSignature({
    rawBody: rawBinary,
    signatureHeader: binSig,
    secret: TEST_SECRET,
    timestampHeader: String(nowSec),
    nowSec,
  });
  assert.equal(binRes.ok, true);
});

test("verifyWebhookSignature fails closed on missing/malformed timestamp, whitespace hex, tampered body, or invalid rawBody", () => {
  const rawBody = JSON.stringify({ tx_ref: "PAY-2026-0001", amount_minor: 150000 });
  const nowSec = 1795650000;
  const sig = `sha256=${signWebhookPayload(rawBody, TEST_SECRET, nowSec)}`;

  // Missing timestamp rejected by default (requireTimestamp = true)
  const missingTs = verifyWebhookSignature({
    rawBody,
    signatureHeader: `sha256=${signWebhookPayload(rawBody, TEST_SECRET)}`,
    secret: TEST_SECRET,
    nowSec,
  });
  assert.equal(missingTs.ok, false);
  assert.equal(missingTs.reason, "missing_timestamp");

  // Non-decimal timestamps (hex / scientific / whitespace) rejected
  for (const badTs of ["0x6b000000", "1e9", " 1795650000", "0", "-10"]) {
    const res = verifyWebhookSignature({
      rawBody,
      signatureHeader: sig,
      secret: TEST_SECRET,
      timestampHeader: badTs,
      nowSec,
    });
    assert.equal(res.ok, false, `Should reject malformed timestamp: ${badTs}`);
    assert.equal(res.reason, "malformed_timestamp");
  }

  // Tampered body rejected
  const tampered = verifyWebhookSignature({
    rawBody: JSON.stringify({ tx_ref: "PAY-2026-0001", amount_minor: 1500000 }),
    signatureHeader: sig,
    secret: TEST_SECRET,
    timestampHeader: String(nowSec),
    nowSec,
  });
  assert.equal(tampered.ok, false);
  assert.equal(tampered.reason, "signature_mismatch");

  // Stale timestamp outside replay window rejected
  const stale = verifyWebhookSignature({
    rawBody,
    signatureHeader: sig,
    secret: TEST_SECRET,
    timestampHeader: String(nowSec - 600),
    nowSec,
    maxSkewSec: 300,
  });
  assert.equal(stale.ok, false);
  assert.equal(stale.reason, "timestamp_outside_window");

  // Whitespace padded signature hex rejected
  const paddedSig = verifyWebhookSignature({
    rawBody,
    signatureHeader: `${sig} `,
    secret: TEST_SECRET,
    timestampHeader: String(nowSec),
    nowSec,
  });
  assert.equal(paddedSig.ok, false);
  assert.equal(paddedSig.reason, "malformed_hex_digest");

  // Non-string/Buffer rawBody fails closed cleanly
  const badBody = verifyWebhookSignature({
    rawBody: { parsed: true },
    signatureHeader: sig,
    secret: TEST_SECRET,
    timestampHeader: String(nowSec),
    nowSec,
  });
  assert.equal(badBody.ok, false);
  assert.equal(badBody.reason, "invalid_raw_body");
});

test("DoubleEntryLedger prevents colon-injection cross-tenant collisions, replay attacks, and integer overflow", () => {
  const ledger = new DoubleEntryLedger();
  ledger.createAccount({ tenantId: "a", accountId: "b:c", currency: "DZD", initialBalanceMinor: 500000 });
  ledger.createAccount({ tenantId: "a:b", accountId: "c", currency: "DZD", initialBalanceMinor: 100000 });
  ledger.createAccount({ tenantId: "a", accountId: "merchant", currency: "DZD", initialBalanceMinor: 0 });

  assert.equal(ledger.getBalance("a", "b:c"), 500000);
  assert.equal(ledger.getBalance("a:b", "c"), 100000);

  const first = ledger.postTransfer({
    tenantId: "a",
    txRef: "BM-882419",
    debitAccountId: "b:c",
    creditAccountId: "merchant",
    amountMinor: 150000,
    currency: "DZD",
  });
  assert.equal(first.ok, true);
  assert.equal(first.status, 201);
  assert.equal(ledger.getBalance("a", "b:c"), 350000);
  assert.equal(ledger.getBalance("a", "merchant"), 150000);
  assert.equal(ledger.getBalance("a:b", "c"), 100000);

  // Replay attack with whitespace and lower-case variant of same reference
  const replay = ledger.postTransfer({
    tenantId: "a",
    txRef: "  bm-882419 ",
    debitAccountId: "b:c",
    creditAccountId: "merchant",
    amountMinor: 150000,
    currency: "DZD",
  });
  assert.equal(replay.ok, false);
  assert.equal(replay.status, 409);
  assert.equal(replay.error, "duplicate_transaction_reference");

  // Integer overflow guard
  ledger.createAccount({
    tenantId: "a",
    accountId: "near_max",
    currency: "DZD",
    initialBalanceMinor: Number.MAX_SAFE_INTEGER - 10,
  });
  const overflow = ledger.postTransfer({
    tenantId: "a",
    txRef: "BM-OVERFLOW",
    debitAccountId: "b:c",
    creditAccountId: "near_max",
    amountMinor: 100,
    currency: "DZD",
  });
  assert.equal(overflow.ok, false);
  assert.equal(overflow.status, 422);
  assert.equal(overflow.error, "balance_overflow");

  const balanceCheck = ledger.verifyTrialBalance();
  assert.equal(balanceCheck.balanced, true);
  assert.equal(balanceCheck.entryCount, 1);
});

test("computeReceiptFingerprint is deterministic and immune to delimiter collisions", () => {
  const h1 = computeReceiptFingerprint({ provider: "BaridiMob", txRef: "bm-1029", amountMinor: 4500, currency: "dzd" });
  const h2 = computeReceiptFingerprint({ provider: " baridimob ", txRef: " BM-1029 ", amountMinor: 4500, currency: "DZD" });
  assert.equal(h1, h2);
  assert.equal(h1.length, 64);

  // Delimiter injection test: "a|b" + "c" must never collide with "a" + "b|c"
  const c1 = computeReceiptFingerprint({ provider: "a|b", txRef: "c", amountMinor: 100, currency: "DZD" });
  const c2 = computeReceiptFingerprint({ provider: "a", txRef: "b|c", amountMinor: 100, currency: "DZD" });
  assert.notEqual(c1, c2);
});
