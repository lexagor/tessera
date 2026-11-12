import assert from "node:assert/strict";
import { test } from "node:test";

import { ed25519 } from "@noble/curves/ed25519";
import { readFileSync } from "node:fs";
import type { ReceiptV2 } from "@tessera-verify/receipt-schema";

import { exportAgentReceipt, verifyAgentReceiptSignature } from "../src/index.js";

const fixture = JSON.parse(
  readFileSync(
    new URL("../../receipt-schema/fixtures/receipt-v2-signed.json", import.meta.url),
    "utf8",
  ),
) as { receipt: ReceiptV2 };

const SEED = "0x" + "42".repeat(32);

test("exports and signs an Agent Receipts v0.5.0 credential", () => {
  const credential = exportAgentReceipt({
    authorization: fixture.receipt,
    tenant: "acme",
    issuerDid: "did:web:api.tessera.example",
    signingKey: SEED,
  });
  assert.deepEqual(credential.type, ["VerifiableCredential", "AgentReceipt"]);
  assert.equal(credential.version, "0.5.0");
  assert.equal(credential.credentialSubject.action.type, "financial.payment.initiate");
  assert.equal(credential.proof.type, "Ed25519Signature2020");
  assert.ok(credential.proof.proofValue.startsWith("u"));
  const publicKey = ed25519.getPublicKey(Buffer.from(SEED.slice(2), "hex"));
  assert.equal(verifyAgentReceiptSignature(credential, publicKey), true);
});

test("includes a supplied RFC 3161 timestamp token", () => {
  const credential = exportAgentReceipt({
    authorization: fixture.receipt,
    tenant: "acme",
    issuerDid: "did:web:api.tessera.example",
    signingKey: SEED,
    trustedTimestamp: "dGltZXN0YW1w",
  });
  assert.equal(
    credential.credentialSubject.action.trusted_timestamp,
    "dGltZXN0YW1w",
  );
});

test("rejects a malformed signing key", () => {
  assert.throws(() =>
    exportAgentReceipt({
      authorization: fixture.receipt,
      tenant: "acme",
      issuerDid: "did:web:api.tessera.example",
      signingKey: "0x1234",
    }),
  );
});
