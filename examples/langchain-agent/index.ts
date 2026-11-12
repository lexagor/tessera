/**
 * Example: broker a real LangChain tool call through Tessera.
 *
 * The tool definition and invocation use `@langchain/core`; the wrapper authorizes the
 * exact call before the original tool runs and leaves a signed outcome.
 */
import { DynamicStructuredTool } from "@langchain/core/tools";
import { z } from "zod";

import { wrapLangChainTool } from "@tessera-verify/langchain";
import { createClient } from "@tessera-verify/sdk-ts";

const tessera = createClient({
  endpoint: process.env.TESSERA_ENDPOINT ?? "http://localhost:8787",
  apiKey: process.env.TESSERA_API_KEY ?? "tsk_demo_local",
  agentId: "example-langchain-agent",
  userId: "user_42",
});

const lookupCustomer = new DynamicStructuredTool({
  name: "lookupCustomer",
  description: "Look up one customer by id",
  schema: z.object({ customerId: z.string() }),
  func: async ({ customerId }) => ({ customerId, name: "Ada Lovelace" }),
});

const brokeredLookup = wrapLangChainTool(tessera, lookupCustomer, {
  intent: "answer a support question about this customer's recent orders",
  run: async (args, credential) => {
    if (credential.material.kind === "grant") {
      return tessera.proxy({
        grantId: credential.material.grantId,
        argsHash: credential.argsHash,
        method: "GET",
        path: `/v1/customers/${encodeURIComponent(String(args.customerId))}`,
      });
    }
    return lookupCustomer.invoke({ customerId: String(args.customerId) });
  },
});

async function main() {
  const result = await brokeredLookup.invoke({ customerId: "cus_123" });
  console.log("result:", result);
}

main().catch((error) => {
  console.error("tessera example failed:", String(error));
  process.exitCode = 1;
});
