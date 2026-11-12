import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { validateReceipt, type ReceiptV2 } from "../src/index.ts";

function fixture(): ReceiptV2 {
  const url = new URL("../fixtures/receipt-v2-signed.json", import.meta.url);
  const parsed = JSON.parse(readFileSync(url, "utf8")) as { receipt: ReceiptV2 };
  return structuredClone(parsed.receipt);
}

test("accepts the signed v2 fixture", () => {
  assert.deepEqual(validateReceipt(fixture()), []);
});

test("rejects a mismatched agent binding", () => {
  const receipt = fixture();
  receipt.agentMeta.agentId = "other-agent";
  assert.ok(validateReceipt(receipt).some((error) => error.includes("agentMeta.agentId")));
});

test("rejects a mismatched policy binding", () => {
  const receipt = fixture();
  receipt.policy.policyHash = `0x${"11".repeat(32)}`;
  assert.ok(validateReceipt(receipt).some((error) => error.includes("policy.policyHash")));
});

test("rejects a mismatched credential binding", () => {
  const receipt = fixture();
  receipt.credential!.ttlSeconds = 999;
  assert.ok(validateReceipt(receipt).some((error) => error.includes("ttlSeconds")));
});

test("rejects a malformed result hash", () => {
  const receipt = fixture();
  receipt.call.resultHash = "0xnot-a-hash";
  assert.ok(validateReceipt(receipt).some((error) => error.includes("call.resultHash")));
});

test("rejects an unknown outcome status", () => {
  const receipt = fixture();
  receipt.outcome = {
    status: "made-up",
    completedAt: "2026-11-06T12:00:05Z",
  };
  assert.ok(validateReceipt(receipt).some((error) => error.includes("outcome.status")));
});

test("rejects an unknown outcome source", () => {
  const receipt = fixture();
  receipt.outcome = {
    status: "success",
    source: "made-up" as never,
    completedAt: "2026-11-06T12:00:05Z",
  };
  assert.ok(validateReceipt(receipt).some((error) => error.includes("outcome.source")));
});

test("rejects a malformed authorization receipt link", () => {
  const receipt = fixture();
  receipt.authorizationReceiptId = "0xnot-a-hash";
  assert.ok(
    validateReceipt(receipt).some((error) => error.includes("authorizationReceiptId")),
  );
});

test("rejects an unsupported schema version", () => {
  const receipt = fixture() as unknown as { v: number };
  receipt.v = 3;
  assert.ok(validateReceipt(receipt as unknown as ReceiptV2).some((error) => error.includes("unsupported")));
});
