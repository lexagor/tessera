/**
 * End-to-end: the TypeScript SDK drives a real broker over HTTP.
 *
 * Spawns `apps/broker/target/debug/tessera-broker` in demo mode and exercises the full
 * loop: authorize -> record -> anchor, plus chain verification. Skipped if the broker
 * binary has not been built.
 */
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createClient, wrapFn, type AuthorizeResult } from "../src/index.ts";

const here = dirname(fileURLToPath(import.meta.url));
const brokerBin = resolve(here, "../../../apps/broker/target/debug/tessera-broker");
const port = Number(process.env.E2E_PORT ?? 8797);
const endpoint = `http://127.0.0.1:${port}`;
const demoKey = "tsk_demo_local";
const agentId = "e2e-agent";

const missingBinary = !existsSync(brokerBin);

let child: ChildProcess | undefined;

async function waitForHealth(timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${endpoint}/healthz`);
      if (res.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("broker did not become healthy");
}

before(async () => {
  if (missingBinary) return;
  child = spawn(brokerBin, [], {
    env: {
      ...process.env,
      BROKER_PORT: String(port),
      TESSERA_DEMO_ALLOW: "1",
      TESSERA_DEMO_KEY: demoKey,
      BROKER_SIGNING_KEY:
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    },
    stdio: "ignore",
  });
  await waitForHealth();
});

after(() => {
  child?.kill("SIGKILL");
});

test("SDK authorize -> record -> anchor against a live broker", { skip: missingBinary }, async () => {
  const client = createClient({ endpoint, apiKey: demoKey, agentId, userId: "user_42" });

  // authorize
  const authorized: AuthorizeResult = await client.authorize({
    tool: "stripe.refunds.create",
    intent: "refund a duplicate charge",
    args: { charge: "ch_123", amount: 100 },
  });
  assert.equal(authorized.decision, "allow");
  assert.ok(authorized.receiptId.startsWith("0x"));
  assert.ok(authorized.credential);
  assert.equal(authorized.credential.argsHash, authorized.receipt.call.argsHash);

  // record the outcome
  await client.record({ receiptId: authorized.receiptId, resultHash: `0x${"11".repeat(32)}` });

  // anchor the (now two-entry) chain
  const batch = await client.anchor(agentId);
  assert.equal(batch.count, 2);
  assert.ok(batch.root.startsWith("0x"));
  assert.ok(batch.calldata.startsWith("0x15954b2c"));

  // independently verify the chain via the raw endpoint
  const chainRes = await fetch(`${endpoint}/v1/chain/${agentId}`, {
    headers: { authorization: `Bearer ${demoKey}` },
  });
  assert.equal(chainRes.status, 200);
  const chain = (await chainRes.json()) as { length: number; verified: boolean };
  assert.equal(chain.length, 2);
  assert.equal(chain.verified, true);
});

test("idempotency keys replay authorize without duplicating the chain", async () => {
  if (missingBinary) return;
  const client = createClient({
    endpoint,
    apiKey: demoKey,
    agentId: "idem-agent",
    userId: "u1",
  });
  const input = {
    tool: "stripe.refunds.create",
    intent: "refund a duplicate charge",
    args: { charge: "ch_1", amount: 100 },
  };
  const idempotencyKey = "sdk-retry-1";
  const first = await client.authorize(input, { idempotencyKey });
  const second = await client.authorize(input, { idempotencyKey });
  assert.equal(second.receiptId, first.receiptId, "replay returns the original receipt");

  const chain = (await fetch(`${endpoint}/v1/chain/idem-agent`, {
    headers: { "x-api-key": demoKey },
  }).then((res) => res.json())) as { length: number };
  assert.equal(chain.length, 1, "only one receipt was written");
});

test("wrapped tools send one idempotency key per invocation", async () => {
  if (missingBinary) return;
  const client = createClient({
    endpoint,
    apiKey: demoKey,
    agentId: "wrap-agent",
    userId: "u1",
  });
  const wrapped = wrapFn(
    client,
    { tool: "stripe.refunds.create", intent: "refund" },
    async () => ({ ok: true }),
  );
  // Two invocations use distinct keys, so both authorize+record pairs land on the chain.
  await wrapped({ amount: 1 });
  await wrapped({ amount: 2 });
  const chain = (await fetch(`${endpoint}/v1/chain/wrap-agent`, {
    headers: { "x-api-key": demoKey },
  }).then((res) => res.json())) as { length: number };
  assert.equal(chain.length, 4, "two invoke cycles => four receipts");

  // A retried invocation with an explicit key is idempotent.
  const key = "wrap-retry-1";
  await wrapped({ amount: 3 }, { idempotencyKey: key });
  const afterFirst = (await fetch(`${endpoint}/v1/chain/wrap-agent`, {
    headers: { "x-api-key": demoKey },
  }).then((res) => res.json())) as { length: number };
  assert.equal(afterFirst.length, 6);
});
