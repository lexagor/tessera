import assert from "node:assert/strict";
import { test } from "node:test";

import { DynamicStructuredTool } from "@langchain/core/tools";
import { z } from "zod";
import type { TesseraClient } from "@tessera/sdk-ts";

import { wrapLangChainTool } from "../src/index.js";

function tool(): DynamicStructuredTool {
  return new DynamicStructuredTool({
    name: "lookup_customer",
    description: "Look up one customer",
    schema: z.object({ customerId: z.string() }),
    func: async () => "original",
  });
}

function bearerClient(observed: { records: number }): TesseraClient {
  return {
    authorize: async () => ({
      decision: "allow",
      reason: "test",
      credential: {
        provider: "internal",
        resource: "internal:lookup",
        ttlSeconds: 30,
        singleUse: true,
        argsHash: `0x${"11".repeat(32)}`,
        material: { kind: "bearer", token: "secret" },
      },
      receipt: {},
      receiptId: `0x${"22".repeat(32)}`,
      actionId: "action_1",
    }),
    record: async () => {
      observed.records += 1;
    },
  } as unknown as TesseraClient;
}

test("brokers a LangChain tool and records a direct-credential outcome", async () => {
  const observed = { records: 0 };
  const wrapped = wrapLangChainTool(bearerClient(observed), tool(), {
    intent: "look up a customer",
    run: async (args, credential) => {
      assert.equal(args.customerId, "cus_1");
      assert.equal(credential.material.kind, "bearer");
      return "brokered";
    },
  });
  const result = await wrapped.invoke({ customerId: "cus_1" });
  assert.equal(result, "brokered");
  assert.equal(observed.records, 1);
});

test("does not self-report a broker-observed grant outcome", async () => {
  const observed = { records: 0 };
  const client = {
    authorize: async () => ({
      decision: "allow",
      reason: "test",
      credential: {
        provider: "internal",
        resource: "internal:lookup",
        ttlSeconds: 30,
        singleUse: true,
        argsHash: `0x${"11".repeat(32)}`,
        material: { kind: "grant", grantId: "grant_internal_1", proxyRequired: true },
      },
      receipt: {},
      receiptId: `0x${"22".repeat(32)}`,
      actionId: "action_2",
    }),
    record: async () => {
      observed.records += 1;
    },
  } as unknown as TesseraClient;
  const wrapped = wrapLangChainTool(client, tool(), {
    intent: "look up a customer",
    run: async () => ({ outcomeRecorded: true }),
  });
  await wrapped.invoke({ customerId: "cus_1" });
  assert.equal(observed.records, 0);
});
