/**
 * Reference governed agent: the full Tessera loop.
 *
 *   1. authorize  — declare intent, get an ephemeral credential + signed receipt
 *   2. execute    — use the credential directly (bearer/AWS) or via the broker proxy (grant)
 *   3. record     — append the linked outcome receipt
 *   4. anchor     — Merkle batch of the agent's receipt chain
 *
 * Run against a local broker in demo mode:
 *   BROKER_PORT=8787 TESSERA_DEMO_ALLOW=1 tessera-broker &
 *   TESSERA_API_KEY=tsk_demo_local pnpm start
 */
import { createClient, hashResult, type EphemeralCredential } from "@tessera-verify/sdk-ts";

const tessera = createClient({
  endpoint: process.env.TESSERA_ENDPOINT ?? "http://localhost:8787",
  apiKey: process.env.TESSERA_API_KEY ?? "tsk_demo_local",
  agentId: "governed-agent",
  userId: "user_42",
});

async function execute(credential: EphemeralCredential, args: Record<string, unknown>) {
  switch (credential.material.kind) {
    case "bearer":
      return { via: "bearer", tokenPreview: credential.material.token.slice(0, 8) };
    case "aws_sts":
      return { via: "aws-sts", accessKeyId: credential.material.accessKeyId };
    case "grant":
      return {
        via: "proxy",
        response: await tessera.proxy({
          grantId: credential.material.grantId,
          argsHash: credential.argsHash,
          method: "POST",
          path: "/v1/refunds",
          body: `amount=${args.amount}`,
        }),
      };
  }
}

async function main() {
  const args = { charge: "ch_123", amount: 4200 };

  const authorized = await tessera.authorize({
    tool: "stripe.refunds.create",
    intent: "refund a duplicate charge for a customer",
    args,
  });
  console.log(`1. authorize -> ${authorized.decision} (policy: ${authorized.receipt.authorization.policy})`);
  if (authorized.decision !== "allow" || !authorized.credential) {
    console.error(`   denied: ${authorized.reason}`);
    return;
  }

  const outcome = await execute(authorized.credential, args);
  console.log(`2. execute   -> ${JSON.stringify(outcome)}`);

  await tessera.record({
    receiptId: authorized.receiptId,
    resultHash: hashResult(outcome),
  });
  console.log(`3. record    -> linked outcome to ${authorized.receiptId.slice(0, 14)}…`);

  const batch = await tessera.anchor("governed-agent");
  console.log(
    `4. anchor    -> ${batch.count} receipts, root ${batch.root.slice(0, 18)}…, calldata ${batch.calldata.slice(0, 10)}…`,
  );
}

main().catch((err) => console.error("error:", String(err)));
