import assert from "node:assert/strict";
import { test } from "node:test";

import { wrapMcpDispatcher } from "../dist/index.js";

const ARGS_HASH = `0x${"22".repeat(32)}`;
const RECEIPT_ID = `0x${"11".repeat(32)}`;
const CREDENTIAL = {
  provider: "mock",
  resource: "demo.tool",
  ttlSeconds: 30,
  singleUse: true,
  argsHash: ARGS_HASH,
  material: { kind: "bearer", token: "test-token" },
};

function fakeClient(decision = "allow", credential = CREDENTIAL) {
  const calls = [];
  return {
    calls,
    async authorize(input) {
      calls.push({ type: "authorize", input });
      return {
        decision,
        reason: decision === "allow" ? "ok" : "denied",
        receiptId: RECEIPT_ID,
        credential: decision === "allow" ? credential : undefined,
      };
    },
    async record(input) {
      calls.push({ type: "record", input });
    },
  };
}

test("records a successful MCP tool call with a real result hash", async () => {
  const client = fakeClient();
  const wrapped = wrapMcpDispatcher(client, async () => ({
    content: [{ type: "text", text: "ok" }],
  }));
  const out = await wrapped({ name: "demo.tool", arguments: { amount: 1 } });
  assert.equal(out.content[0].text, "ok");
  assert.equal(client.calls.length, 2);
  const recorded = client.calls[1].input;
  assert.equal(recorded.receiptId, RECEIPT_ID);
  assert.equal(recorded.status, "success");
  assert.match(recorded.resultHash, /^0x[0-9a-f]{64}$/);
});

test("records a failure outcome and rethrows", async () => {
  const client = fakeClient();
  const wrapped = wrapMcpDispatcher(client, async () => {
    throw new TypeError("provider failed");
  });
  await assert.rejects(
    () => wrapped({ name: "demo.tool", arguments: {} }),
    /provider failed/,
  );
  const recorded = client.calls[1].input;
  assert.equal(recorded.status, "failure");
  assert.equal(recorded.errorClass, "TypeError");
  assert.match(recorded.resultHash, /^0x[0-9a-f]{64}$/);
});

test("does not self-report a broker-observed grant outcome", async () => {
  const client = fakeClient("allow", {
    ...CREDENTIAL,
    material: { kind: "grant", grantId: "grant_mock_1", proxyRequired: true },
  });
  const wrapped = wrapMcpDispatcher(client, async () => ({
    content: [{ type: "text", text: "ok" }],
  }));
  await wrapped({ name: "demo.tool", arguments: {} });
  assert.equal(client.calls.length, 1);
});

test("does not record when authorization is denied", async () => {
  const client = fakeClient("deny");
  const wrapped = wrapMcpDispatcher(client, async () => ({
    content: [{ type: "text", text: "should not run" }],
  }));
  const out = await wrapped({ name: "demo.tool", arguments: {} });
  assert.equal(out.isError, true);
  assert.equal(client.calls.length, 1);
});
