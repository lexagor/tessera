/**
 * Example: a Vercel AI SDK tool whose execution is brokered by Tessera.
 *
 * The tool definition is a normal AI SDK tool. The `execute` function calls the
 * Tessera-wrapped provider function, so every model-initiated invocation is authorized,
 * bound to an ephemeral credential, and recorded.
 */
import { tool, type Tool } from "ai";
import { z } from "zod";

import { createClient, wrapFn, type EphemeralCredential } from "@tessera-verify/sdk-ts";

const tessera = createClient({
  endpoint: process.env.TESSERA_ENDPOINT ?? "http://localhost:8787",
  apiKey: process.env.TESSERA_API_KEY ?? "tsk_demo_local",
  agentId: process.env.TESSERA_AGENT_ID ?? "vercel-ai-agent",
  userId: process.env.TESSERA_USER_ID ?? "user_42",
  authorityToken: process.env.TESSERA_AUTHORITY_TOKEN,
});

async function refundProvider(
  args: Record<string, unknown>,
  credential: EphemeralCredential,
) {
  // Replace this with the real provider call, for example:
  //   stripe.refunds.create({ charge, amount }, { apiKey: credential.material.token })
  if (credential.material.kind !== "bearer") {
    throw new Error("this example expects a scoped bearer credential");
  }
  return {
    refunded: true,
    charge: args.charge,
    amount: args.amount,
    providerCredential: credential.material.token ? "present" : "missing",
  };
}

const brokeredRefund = wrapFn(
  tessera,
  {
    tool: "stripe.refunds.create",
    intent: "refund a duplicate customer charge",
    declaredPurpose: "billing-support",
    riskClass: "financial",
  },
  refundProvider,
);

export const refundTool: Tool = tool({
  description: "Refund one duplicate charge after policy authorization.",
  inputSchema: z.object({
    charge: z.string().describe("Stripe charge id"),
    amount: z.number().int().positive().describe("Amount in the smallest currency unit"),
  }),
  execute: async (args) => brokeredRefund(args),
});

/**
 * Wire `refundTool` into your model call:
 *
 *   import { generateText } from "ai";
 *   import { openai } from "@ai-sdk/openai";
 *
 *   const result = await generateText({
 *     model: openai("gpt-4.1-mini"),
 *     tools: { refund: refundTool },
 *     prompt: "Refund charge ch_123 for 4200 cents.",
 *   });
 */
