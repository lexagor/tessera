/**
 * Example: an agent refunds a Stripe charge without ever holding the secret key.
 *
 * Stripe has no per-request STS, so Tessera returns a broker-held grant. The agent calls
 * the Tessera proxy, which redeems the grant and forwards the request to Stripe with the
 * narrowest restricted key.
 *
 * Status: scaffold.
 */
import { createClient, hashResult } from "@tessera-verify/sdk-ts";

const tessera = createClient({
  endpoint: process.env.TESSERA_ENDPOINT ?? "http://localhost:8787",
  apiKey: process.env.TESSERA_API_KEY ?? "tsk_demo_local",
  agentId: "billing-support-agent",
  userId: "agent_on_behalf_of_support_team",
});

async function main() {
  const args = { charge: "ch_123", amount: 4200 };
  const authorized = await tessera.authorize({
    tool: "stripe.refunds.create",
    intent: "refund a duplicate charge for a customer",
    args,
  });

  if (authorized.decision !== "allow" || !authorized.credential) {
    console.error("denied:", authorized.reason);
    return;
  }

  const { material, argsHash } = authorized.credential;
  if (material.kind !== "grant") {
    console.log("unexpected credential material:", material.kind);
    return;
  }

  const resp = await tessera.proxy({
    grantId: material.grantId,
    argsHash,
    method: "POST",
    path: "/v1/refunds",
    body: `charge=${encodeURIComponent(String(args.charge))}&amount=${args.amount}`,
  });

  console.log("stripe responded:", resp.status, resp.body);
  await tessera.record({ receiptId: authorized.receiptId, resultHash: hashResult({ status: resp.status }) });
}

main().catch((err) => console.error("error:", String(err)));
