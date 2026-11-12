/**
 * Cross-language parity: the shared fixtures in `../fixtures/` are hashed here (TypeScript)
 * and in `apps/broker/tests/parity.rs` (Rust). Both must agree on the canonical JSON and
 * Keccak-256 payload hash.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  canonicalize,
  payloadHash,
  toolDefinitionHash,
  type Receipt,
  type ReceiptV2,
} from "../src/index.ts";

function load<T>(name: string): T {
  const url = new URL(`../fixtures/${name}`, import.meta.url);
  return JSON.parse(readFileSync(url, "utf8")) as T;
}

test("fixture payload hashes match the golden values", () => {
  const receipts = load<Receipt[]>("receipts.json");
  const expected = load<string[]>("expected.json");

  assert.equal(receipts.length, expected.length);
  receipts.forEach((receipt, i) => {
    assert.equal(payloadHash(receipt), expected[i], `receipt ${i}`);
  });
});

test("signed v2 fixture hashes match the golden value", () => {
  const fixture = load<{ expectedPayloadHash: string; receipt: ReceiptV2 }>(
    "receipt-v2-signed.json",
  );
  assert.equal(payloadHash(fixture.receipt), fixture.expectedPayloadHash);
});

test("canonical numbers match Rust normalization", () => {
  assert.equal(canonicalize({ a: 0 }), '{"a":0}');
  assert.equal(canonicalize({ a: 0.5 }), '{"a":0.5}');
  assert.equal(canonicalize({ a: 0.03 }), '{"a":0.03}');
  assert.equal(canonicalize({ b: 1, a: 1 }), '{"a":1,"b":1}');
});

test("tool definition hashes match the Rust broker", () => {
  const definitions = load<unknown[]>("tool-definitions.json");
  const expected = load<string[]>("tool-expected.json");

  assert.equal(definitions.length, expected.length);
  definitions.forEach((definition, i) => {
    assert.equal(toolDefinitionHash(definition), expected[i], `definition ${i}`);
  });
});
