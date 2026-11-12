import assert from "node:assert/strict";
import { test } from "node:test";

process.env.NODE_ENV = "test";
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? "postgres://unused";
process.env.OIDC_STATE_SECRET = "oidc-state-test-secret-at-least-32-bytes";

const { decodeOidcState, encodeOidcState } = await import("../src/oidc-state.js");

test("OIDC state round-trips with a valid signature", () => {
  const encoded = encodeOidcState({ state: "state", nonce: "nonce", verifier: "verifier" });
  const decoded = decodeOidcState(encoded);
  assert.equal(decoded?.state, "state");
  assert.equal(decoded?.nonce, "nonce");
  assert.equal(decoded?.verifier, "verifier");
});

test("OIDC state rejects tampering and malformed values", () => {
  const encoded = encodeOidcState({ state: "state", nonce: "nonce", verifier: "verifier" });
  const [payload, signature] = encoded.split(".");
  assert.ok(payload && signature);
  const tampered = `${payload}.${signature.slice(0, -1)}${signature.endsWith("A") ? "B" : "A"}`;
  assert.equal(decodeOidcState(tampered), null);
  assert.equal(decodeOidcState(`${payload}.${signature}.extra`), null);
  assert.equal(decodeOidcState("not-a-state"), null);
});
