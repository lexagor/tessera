import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { verifyReceipt } from "@tessera-verify/verify";

import { buildTrustView, extractRecords, tamperPayload } from "../src/view-model.js";

const fixture = JSON.parse(
  readFileSync(new URL("../../../packages/receipt-schema/fixtures/receipt-v2-signed.json", import.meta.url), "utf8"),
) as {
  domain: { chainId: number; verifyingContract: string };
  expectedSigner: string;
  receipt: Record<string, any>;
};

test("builds the chain-of-trust entities from a signed receipt", () => {
  const view = buildTrustView({
    authorization: fixture.receipt,
    verification: { valid: true, recovered: fixture.expectedSigner },
  });
  assert.equal(view.entities.length, 8);
  assert.equal(view.entities.find((entity) => entity.id === "agent")?.title, "billing-agent");
  assert.equal(view.entities.find((entity) => entity.id === "tool")?.title, "stripe.refunds.create");
  assert.equal(view.entities.find((entity) => entity.id === "signature")?.state, "valid");
  assert.equal(view.enforcement.level, "Level 1");
  assert.match(view.summary, /billing-agent/);
});

test("labels scoped credentials and caller-asserted authority", () => {
  const scoped = buildTrustView({
    authorization: {
      ...fixture.receipt,
      credential: { issuer: "stripe" },
    },
    verification: { valid: true, recovered: fixture.expectedSigner },
  });
  assert.equal(scoped.enforcement.level, "Level 2");
  assert.equal(scoped.enforcement.label, "Level 2 · scoped credential");

  const caller = buildTrustView({
    authorization: {
      ...fixture.receipt,
      credential: {},
    },
    verification: { valid: true, recovered: fixture.expectedSigner },
  });
  assert.equal(caller.enforcement.level, "Caller-asserted");
  assert.equal(caller.enforcement.label, "Caller-asserted authority");
});

test("tampering one signed field invalidates the receipt", () => {
  const tampered = tamperPayload({ receipt: fixture.receipt });
  const result = verifyReceipt(
    tampered.receipt as never,
    fixture.domain,
    fixture.expectedSigner,
  );
  assert.equal(result.valid, true);
  assert.equal(result.matchesExpected, false);
});

test("extractRecords supports direct receipts and chains", () => {
  const direct = extractRecords({ receipt: fixture.receipt });
  assert.equal(direct.authorization?.agent, "billing-agent");
  const chain = extractRecords({
    entries: [
      { receipt: fixture.receipt },
      { receipt: { ...fixture.receipt, nonce: "0x02" } },
    ],
  });
  assert.equal(chain.chainLength, 2);
  assert.equal(chain.authorization?.nonce, "0x02");
});
