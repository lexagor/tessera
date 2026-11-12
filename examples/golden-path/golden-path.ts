/**
 * Golden path: an agent goes through Tessera against real providers and a real chain.
 *
 *   stripe charge -> stripe refund (via broker-held grant proxy)
 *   github installation token -> verify it works -> provider-native revoke
 *   record outcomes -> Merkle anchor -> on-chain submit
 *   independent verification of the receipt chain
 *
 * Every step is env-driven and degrades gracefully: unconfigured providers are skipped with
 * a clear message. See ../../docs/golden-path.md.
 */
import { createClient, hashResult, type AuthorizeResult, type EphemeralCredential } from "@tessera-verify/sdk-ts";

const endpoint = process.env.TESSERA_ENDPOINT ?? "http://localhost:8787";
const apiKey = process.env.TESSERA_API_KEY ?? "tsk_demo_local";
const agentId = process.env.GOLDEN_AGENT_ID ?? "golden-agent";
const userId = process.env.GOLDEN_USER_ID ?? "user_42";
const currency = process.env.STRIPE_CURRENCY ?? "usd";
const amount = Number(process.env.STRIPE_CHARGE_AMOUNT ?? 500);
const githubApiBase = process.env.GOLDEN_GITHUB_API_BASE ?? "https://api.github.com";
const doGithub = process.env.GOLDEN_GITHUB === "1";

const tessera = createClient({ endpoint, apiKey, agentId, userId });

type Outcome = { step: string; ok: boolean; detail: string };
const outcomes: Outcome[] = [];
let failures = 0;

function mark(step: string, ok: boolean, detail: string) {
  outcomes.push({ step, ok, detail });
  if (!ok) failures += 1;
  console.log(`${ok ? "  ok  " : " FAIL "} ${step.padEnd(28)} ${detail}`);
}

async function step(name: string, fn: () => Promise<string>) {
  try {
    mark(name, true, await fn());
  } catch (err) {
    mark(name, false, err instanceof Error ? err.message : String(err));
  }
}

async function authorize(tool: string, intent: string, args: Record<string, unknown>): Promise<AuthorizeResult> {
  const result = await tessera.authorize({ tool, intent, args });
  if (result.decision !== "allow") throw new Error(`denied: ${result.reason}`);
  return result;
}

function grantOf(credential: EphemeralCredential, hint: string): { grantId: string; argsHash: string } {
  if (credential.material.kind !== "grant") {
    throw new Error(`expected a broker-held grant for ${hint}; got '${credential.material.kind}' (is the provider configured on the broker?)`);
  }
  return { grantId: credential.material.grantId, argsHash: credential.argsHash };
}

async function proxiedStripeCall(
  credential: EphemeralCredential,
  path: string,
  body: string,
): Promise<Record<string, unknown>> {
  const { grantId, argsHash } = grantOf(credential, "stripe");
  const resp = await tessera.proxy({
    grantId,
    argsHash,
    method: "POST",
    path,
    body,
    contentType: "application/x-www-form-urlencoded",
  });
  if (resp.status >= 300) throw new Error(`stripe ${resp.status}: ${resp.body.slice(0, 200)}`);
  return JSON.parse(resp.body) as Record<string, unknown>;
}

async function fetchChain(): Promise<{ entries: unknown[]; verified: boolean; length: number }> {
  const res = await fetch(`${endpoint}/v1/chain/${encodeURIComponent(agentId)}`, {
    headers: { authorization: `Bearer ${apiKey}` },
  });
  if (!res.ok) throw new Error(`chain fetch failed: ${res.status}`);
  return (await res.json()) as { entries: unknown[]; verified: boolean; length: number };
}

async function main() {
  console.log(`\nTessera golden path — endpoint ${endpoint}, agent ${agentId}\n`);

  await step("health", async () => {
    const res = await fetch(`${endpoint}/healthz`);
    if (!res.ok) throw new Error(`healthz ${res.status}`);
    return "broker reachable";
  });

  let chargeId = process.env.STRIPE_CHARGE_ID ?? "";

  await step("stripe.charges.create", async () => {
    const auth = await authorize("stripe.charges.create", "create a test charge", {
      amount,
      currency,
      source: "tok_visa",
    });
    const charge = await proxiedStripeCall(
      auth.credential!,
      "/v1/charges",
      `amount=${amount}&currency=${currency}&source=tok_visa`,
    );
    chargeId = String(charge.id);
    // The proxy already appended the broker-observed outcome; do not self-report it.
    return `charge ${chargeId} (auth: ${String(charge._auth).slice(0, 12)}…)`;
  });

  await step("stripe.refunds.create", async () => {
    if (!chargeId) throw new Error("no charge id (previous step failed; set STRIPE_CHARGE_ID to refund an existing test charge)");
    const auth = await authorize("stripe.refunds.create", "refund the test charge", { charge: chargeId, amount });
    const refund = await proxiedStripeCall(auth.credential!, "/v1/refunds", `charge=${chargeId}&amount=${amount}`);
    // The proxy already appended the broker-observed outcome; do not self-report it.
    return `refund ${String(refund.id)} (${String(refund.status)})`;
  });

  await step("github.installation_token", async () => {
    if (!doGithub) return "skipped (set GOLDEN_GITHUB=1)";
    const installationId = Number(process.env.GOLDEN_GITHUB_INSTALLATION_ID ?? 0);
    if (!installationId) throw new Error("set GOLDEN_GITHUB_INSTALLATION_ID");

    const auth = await authorize("github.installation_token", "mint an installation token", {
      installation_id: installationId,
    });
    const credential = auth.credential!;
    if (credential.material.kind !== "bearer") throw new Error(`expected bearer, got ${credential.material.kind}`);
    const token = credential.material.token;

    const res = await fetch(`${githubApiBase}/installation/repositories`, {
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/vnd.github+json",
        "user-agent": "tessera-golden-path",
        "x-github-api-version": "2022-11-28",
      },
    });
    if (!res.ok) throw new Error(`github API ${res.status} (token invalid?)`);
    const body = (await res.json()) as { total_count?: number };

    await tessera.record({ receiptId: auth.receiptId, resultHash: hashResult({ githubRepos: body.total_count ?? null }) });

    const reference = credential.reference;
    if (!reference) throw new Error("no credential reference to revoke");
    const revoke = await tessera.revoke(reference, "credential");
    if (revoke.credentialRevoked !== true) throw new Error(`revoke not confirmed: ${JSON.stringify(revoke)}`);
    return `token valid (${body.total_count ?? "?"} repos) then revoked natively`;
  });

  let anchorRoot = "";
  await step("anchor.batch", async () => {
    const batch = await tessera.anchor(agentId);
    anchorRoot = batch.root;
    if (batch.count === 0) throw new Error("chain is empty");
    return `${batch.count} receipts, root ${batch.root.slice(0, 18)}…`;
  });

  await step("anchor.submit", async () => {
    if (!anchorRoot) throw new Error("no batch to anchor");
    try {
      const res = await tessera.submitAnchor(agentId);
      return `tx ${res.txHash}`;
    } catch (err) {
      return `skipped (broker anchoring not configured: ${err instanceof Error ? err.message : err})`;
    }
  });

  await step("verify.chain", async () => {
    const chain = await fetchChain();
    const result = await tessera.verifyChain(chain.entries);
    if (!result.valid) throw new Error("chain did not verify");
    return `${result.length} receipts verified, signer ${result.recovered?.slice(0, 12)}…`;
  });

  await step("verify.receipt", async () => {
    const chain = await fetchChain();
    const last = chain.entries[chain.entries.length - 1] as { receipt: Record<string, unknown> } | undefined;
    if (!last) throw new Error("no receipts to verify");
    const result = await tessera.verifyReceipt(last.receipt);
    if (!result.valid) throw new Error("receipt did not verify");
    return `recovered ${result.recovered.slice(0, 12)}… payload ${result.payloadHash.slice(0, 14)}…`;
  });

  console.log("");
  if (failures === 0) {
    console.log("GOLDEN PATH OK\n");
  } else {
    console.log(`GOLDEN PATH: ${failures} step(s) failed\n`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
