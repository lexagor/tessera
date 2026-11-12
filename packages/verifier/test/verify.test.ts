import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";
import { AnyReceipt, ReceiptV2, payloadHash } from "@tessera-verify/receipt-schema";

import {
  VerifyDomain,
  eip712Digest,
  verifyAction,
  verifyChain,
  verifyReceipt,
} from "../src/index.js";

const fixture = JSON.parse(
  readFileSync(new URL("../../receipt-schema/fixtures/receipt-v2-signed.json", import.meta.url), "utf8"),
) as {
  domain: VerifyDomain;
  expectedSigner: string;
  expectedPayloadHash: string;
  receipt: ReceiptV2;
};

const PRIVATE_KEY = hexToBytes(
  "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
);

function sign(receipt: AnyReceipt, domain: VerifyDomain): AnyReceipt {
  const copy = structuredClone(receipt);
  copy.signature = null;
  const digest = eip712Digest(copy, domain);
  const signature = secp256k1.sign(digest, PRIVATE_KEY);
  copy.signature = `0x${bytesToHex(
    concatBytes(signature.toCompactRawBytes(), Uint8Array.from([signature.recovery + 27])),
  )}`;
  return copy;
}

test("verifies the signed v2 fixture offline", () => {
  const result = verifyReceipt(fixture.receipt, fixture.domain, fixture.expectedSigner);
  assert.equal(result.valid, true);
  assert.equal(result.recovered, fixture.expectedSigner);
  assert.equal(result.matchesExpected, true);
  assert.equal(result.payloadHash, fixture.expectedPayloadHash);
});

test("detects a tampered v2 record", () => {
  const tampered = structuredClone(fixture.receipt);
  tampered.call.argsHash = `0x${"42".repeat(32)}`;
  const result = verifyReceipt(tampered, fixture.domain, fixture.expectedSigner);
  assert.equal(result.matchesExpected, false);
  assert.notEqual(result.payloadHash, fixture.expectedPayloadHash);
});

test("rejects an empty chain", () => {
  const result = verifyChain([], fixture.domain);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((error) => error.includes("empty")));
});

test("rejects a high-S malleable signature", () => {
  const raw = hexToBytes(fixture.receipt.signature!.replace(/^0x/, ""));
  const s = BigInt(`0x${bytesToHex(raw.slice(32, 64))}`);
  const highS = secp256k1.CURVE.n - s;
  const highBytes = hexToBytes(highS.toString(16).padStart(64, "0"));
  const malleable = structuredClone(fixture.receipt);
  malleable.signature = `0x${bytesToHex(concatBytes(raw.slice(0, 32), highBytes, raw.slice(64)))}`;
  const result = verifyReceipt(malleable, fixture.domain);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((error) => error.includes("low-S")));
});

test("rejects a v2 record missing binding fields", () => {
  const broken = structuredClone(fixture.receipt) as Partial<ReceiptV2>;
  delete broken.principal;
  const result = verifyReceipt(broken as ReceiptV2, fixture.domain);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((error) => error.includes("principal")));
});

test("verifies an authorization/outcome pair", () => {
  const authorization = fixture.receipt;
  const outcome = structuredClone(authorization);
  outcome.prev = payloadHash(authorization);
  outcome.nonce = `0x${"44".repeat(32)}`;
  outcome.ts = "2026-11-06T12:00:05Z";
  outcome.call.resultHash = `0x${"55".repeat(32)}`;
  outcome.outcome = {
    status: "success",
    resultHash: outcome.call.resultHash,
    externalRef: "re_123",
    completedAt: "2026-11-06T12:00:05Z",
  };
  const signedOutcome = sign(outcome, fixture.domain);
  const result = verifyAction(authorization, signedOutcome, fixture.domain, fixture.expectedSigner);
  assert.equal(result.valid, true);
  assert.equal(result.recovered, fixture.expectedSigner);
});

test("verifies an outcome that links by authorizationReceiptId", () => {
  const authorization = fixture.receipt;
  const intervening = structuredClone(authorization);
  intervening.prev = payloadHash(authorization);
  intervening.nonce = `0x${"88".repeat(32)}`;
  intervening.ts = "2026-11-06T12:00:04Z";
  const later = payloadHash(sign(intervening, fixture.domain));

  const outcome = structuredClone(authorization);
  outcome.prev = later;
  outcome.authorizationReceiptId = payloadHash(authorization);
  outcome.nonce = `0x${"99".repeat(32)}`;
  outcome.ts = "2026-11-06T12:00:05Z";
  outcome.call.resultHash = `0x${"aa".repeat(32)}`;
  outcome.outcome = {
    status: "success",
    source: "broker_observed",
    resultHash: outcome.call.resultHash,
    completedAt: "2026-11-06T12:00:05Z",
  };
  const signedOutcome = sign(outcome, fixture.domain);
  const result = verifyAction(authorization, signedOutcome, fixture.domain, fixture.expectedSigner);
  assert.equal(result.valid, true, result.errors.join("; "));
});

test("rejects an outcome with no authorization link", () => {
  const authorization = fixture.receipt;
  const outcome = structuredClone(authorization);
  outcome.prev = `0x${"bb".repeat(32)}`;
  outcome.nonce = `0x${"cc".repeat(32)}`;
  outcome.ts = "2026-11-06T12:00:05Z";
  outcome.call.resultHash = `0x${"dd".repeat(32)}`;
  outcome.outcome = {
    status: "success",
    resultHash: outcome.call.resultHash,
    completedAt: "2026-11-06T12:00:05Z",
  };
  const signedOutcome = sign(outcome, fixture.domain);
  const result = verifyAction(authorization, signedOutcome, fixture.domain, fixture.expectedSigner);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((error) => error.includes("link to authorization")));
});

test("verifies a two-entry chain", () => {
  const authorization = fixture.receipt;
  const outcome = structuredClone(authorization);
  outcome.prev = payloadHash(authorization);
  outcome.nonce = `0x${"66".repeat(32)}`;
  outcome.ts = "2026-11-06T12:00:05Z";
  outcome.call.resultHash = `0x${"77".repeat(32)}`;
  outcome.outcome = {
    status: "success",
    resultHash: outcome.call.resultHash,
    completedAt: "2026-11-06T12:00:05Z",
  };
  const signed = sign(outcome, fixture.domain);
  const entries = [
    { payloadHash: payloadHash(authorization), receipt: authorization },
    { payloadHash: payloadHash(signed), receipt: signed },
  ];
  const result = verifyChain(entries, fixture.domain, fixture.expectedSigner);
  assert.equal(result.valid, true);
  assert.equal(result.length, 2);
});
