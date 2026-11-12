import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import { after, test } from "node:test";

const databaseUrl = process.env.TEST_DATABASE_URL;
const evidenceDir = await mkdtemp(join(tmpdir(), "tessera-api-test-"));
const fixture = JSON.parse(
  readFileSync(
    new URL("../../../packages/receipt-schema/fixtures/receipt-v2-signed.json", import.meta.url),
    "utf8",
  ),
) as {
  domain: { chainId: number; verifyingContract: string };
  expectedSigner: string;
  expectedPayloadHash: string;
  receipt: Record<string, any>;
};

function json(res: ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
}

function outcomeReceipt(): Record<string, any> {
  const receipt = structuredClone(fixture.receipt);
  const resultHash = `0x${"ab".repeat(32)}`;
  receipt.authorizationReceiptId = fixture.expectedPayloadHash;
  receipt.prev = `0x${"cd".repeat(32)}`;
  receipt.call.resultHash = resultHash;
  receipt.outcome = {
    status: "success",
    source: "broker_observed",
    resultHash,
    completedAt: "2026-11-11T12:00:05Z",
  };
  return receipt;
}

const outcome = outcomeReceipt();
const outcomeReceiptId = `0x${"ef".repeat(32)}`;
const liveActionId = `action_${Date.now()}`;

const broker = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname === "/healthz") return json(res, 200, { status: "ok" });
  if (url.pathname === "/v1/verify/domain") {
    return json(res, 200, {
      chainId: fixture.domain.chainId,
      verifyingContract: fixture.domain.verifyingContract,
      signer: fixture.expectedSigner,
      signers: [fixture.expectedSigner],
    });
  }
  if (url.pathname === "/v1/authorize") {
    return json(res, 200, {
      decision: "allow",
      reason: "fixture",
      credential: null,
      receipt: fixture.receipt,
      receiptId: fixture.expectedPayloadHash,
      actionId: liveActionId,
    });
  }
  if (url.pathname === "/v1/proxy") {
    return json(res, 200, {
      status: 200,
      contentType: "application/json",
      body: "{}",
      actionId: liveActionId,
      authorizationReceiptId: fixture.expectedPayloadHash,
      outcomeReceiptId,
      outcomeReceipt: outcome,
      outcomeRecorded: true,
    });
  }
  if (url.pathname === "/v1/policies" && req.method === "GET") {
    return json(res, 200, { items: [] });
  }
  if (url.pathname === "/v1/policies/propose") {
    return json(res, 200, { policy: {}, evidence: [], notes: [] });
  }
  if (url.pathname.startsWith("/v1/policies/")) {
    return json(res, 200, { id: url.pathname.split("/").pop(), version: 1 });
  }
  if (url.pathname === "/v1/transitions" && req.method === "POST") {
    return json(res, 201, {
      id: "kev_2",
      kind: "authority.stepped_up",
      target: "billing-agent",
      details: { transitionType: "authority.stepped_up" },
    });
  }
  if (url.pathname === "/v1/key-events") {
    return json(res, 200, {
      items: [
        {
          id: "kev_1",
          kind: "authority.revoked",
          key_id: "grant_stripe_1",
          key_name: "grant_stripe_1",
          at: "2026-11-11T12:00:00Z",
          event_hash: `0x${"11".repeat(32)}`,
          details: { transitionType: "authority.revoked", target: "grant_stripe_1" },
        },
      ],
      verified: true,
      signaturesValid: true,
    });
  }
  if (url.pathname === "/v1/export/tenant/archive") {
    res.statusCode = 200;
    res.setHeader("content-type", "application/gzip");
    res.end(Buffer.from("fixture archive"));
    return;
  }
  if (url.pathname === "/v1/integrity") {
    return json(res, 200, {
      chains: { agents: 1, receipts: 2, verified: true, unanchoredAgents: 1, drift: [] },
      anchors: { count: 0, latest: null, pending: 0 },
      keyEvents: { count: 1, verified: true, signaturesValid: true, chainValid: true },
    });
  }
  return json(res, 404, { error: `mock broker has no ${req.method} ${url.pathname}` });
});

const brokerPort = await new Promise<number>((resolve, reject) => {
  broker.once("error", reject);
  broker.listen(0, "127.0.0.1", () => {
    const address = broker.address();
    if (!address || typeof address === "string") return reject(new Error("no broker port"));
    resolve(address.port);
  });
});

process.env.NODE_ENV = "test";
process.env.DATABASE_URL = databaseUrl ?? "postgres://unused";
process.env.AUTH_DEV_MODE = "1";
process.env.BROKER_DEMO_ALLOW = "1";
process.env.BROKER_URL = `http://127.0.0.1:${brokerPort}`;
process.env.PUBLIC_BASE_URL = "http://localhost:5173";
process.env.VERIFY_BASE_URL = "https://verify.example";
process.env.CONTROL_PLANE_ENC_KEY = "11".repeat(32);
process.env.AGENT_RECEIPT_ED25519_KEY = `0x${"42".repeat(32)}`;
process.env.AGENT_RECEIPT_ISSUER_DID = "did:web:api.test";
process.env.EVIDENCE_DIR = evidenceDir;

const canRun = Boolean(databaseUrl);

test("control plane routes: auth, actions, evidence, billing, webhooks", { skip: !canRun }, async () => {
  const { migrate, closeDb, db } = await import("../src/db.js");
  await migrate();
  const { app } = await import("../src/index.js");

  const health = await app.request("/healthz");
  assert.equal(health.status, 200);
  const ready = await app.request("/readyz");
  assert.equal(ready.status, 200);
  const openapi = await app.request("/openapi.json");
  assert.equal(openapi.status, 200);
  assert.equal((await app.request("/v1/openapi.json")).status, 200);

  const config = await app.request("/auth/config");
  assert.equal(config.status, 200);
  assert.equal((await config.json()).devAuth, true);

  const login = await app.request("/auth/dev-login", { redirect: "manual" });
  assert.equal(login.status, 302);
  const devCookie = login.headers.get("set-cookie")?.split(";")[0];
  assert.ok(devCookie?.startsWith("tessera_session="));

  // Isolate this suite from other test files that share the dev account.
  const authModule = await import("../src/auth.js");
  const isolatedUser = await authModule.findOrCreateUser({
    email: `routes-${Date.now()}@example.com`,
    name: "Routes Test",
  });
  const isolatedOrg = await authModule.createOrgForUser(isolatedUser, "Routes Test Workspace");
  const isolatedSession = await authModule.createSession(isolatedUser.id, isolatedOrg.id);
  const auth = { cookie: `tessera_session=${isolatedSession.token}` };

  const session = await app.request("/v1/session", { headers: auth });
  assert.equal(session.status, 200);
  const me = await app.request("/v1/me", { headers: auth });
  assert.equal(me.status, 200);
  const meBody = (await me.json()) as { org: { id: string }; role: string };
  assert.equal(meBody.role, "owner");

  await db()`UPDATE orgs SET plan = 'enterprise', name = 'Test Workspace' WHERE id = ${meBody.org.id}`;
  const patched = await app.request("/v1/org", {
    method: "PATCH",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ name: "Test Workspace" }),
  });
  assert.equal(patched.status, 200);

  const members = await app.request("/v1/members", { headers: auth });
  assert.equal(members.status, 200);
  const invite = await app.request("/v1/invites", {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ email: `reviewer-${Date.now()}@example.com`, role: "viewer" }),
  });
  assert.equal(invite.status, 200);
  const inviteBody = (await invite.json()) as { id: string };
  assert.equal((await app.request(`/v1/invites/${inviteBody.id}`, { method: "DELETE", headers: auth })).status, 200);

  const envName = `api-${Date.now()}`;
  const envCreated = await app.request("/v1/environments", {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ name: envName }),
  });
  assert.equal(envCreated.status, 201);
  const environment = (await envCreated.json()) as { id: string; name: string };
  assert.equal(environment.name, envName);
  const envList = await app.request("/v1/environments", { headers: auth });
  assert.equal(envList.status, 200);
  assert.ok(((await envList.json()) as { items: unknown[] }).items.length >= 1);

  const keyCreated = await app.request("/v1/agent-keys", {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ name: "agent-key", expiresInDays: 5 }),
  });
  assert.equal(keyCreated.status, 201);
  const key = (await keyCreated.json()) as { id: string; key: string };
  assert.ok(key.key.startsWith("tsk_live_"));
  assert.equal((await app.request("/v1/agent-keys", { headers: auth })).status, 200);

  const authorized = await app.request("/v1/authorize", {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": key.key },
    body: JSON.stringify({
      agentId: "billing-agent",
      userId: "user_1",
      tool: "stripe.refunds.create",
      intent: "refund",
      args: { charge: "ch_1" },
    }),
  });
  assert.equal(authorized.status, 200);
  const authorization = (await authorized.json()) as { actionId: string; receiptId: string };
  assert.equal(authorization.receiptId, fixture.expectedPayloadHash);

  const actions = await app.request(`/v1/actions?environmentId=${environment.id}`, { headers: auth });
  assert.equal(actions.status, 200);
  assert.equal(((await actions.json()) as { items: unknown[] }).items.length, 1);

  const proxied = await app.request("/v1/proxy", {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": key.key },
    body: JSON.stringify({
      grantId: "grant_stripe_test",
      argsHash: fixture.expectedPayloadHash,
      method: "POST",
      path: "/v1/refunds",
    }),
  });
  assert.equal(proxied.status, 200);
  assert.equal((await proxied.json()).outcomeRecorded, true);

  const detail = await app.request(`/v1/actions/${authorization.actionId}`, { headers: auth });
  assert.equal(detail.status, 200);
  const detailBody = (await detail.json()) as {
    outcomeStatus: string;
    payload: { outcome?: { outcome?: { source?: string } } };
  };
  assert.equal(detailBody.outcomeStatus, "success");
  assert.equal(detailBody.payload.outcome?.outcome?.source, "broker_observed");
  const agentReceipt = await app.request(
    `/v1/actions/${authorization.actionId}/agent-receipt`,
    { headers: auth },
  );
  assert.equal(agentReceipt.status, 200);
  const credential = (await agentReceipt.json()) as {
    version: string;
    proof: { type: string; proofValue: string };
  };
  assert.equal(credential.version, "0.5.0");
  assert.equal(credential.proof.type, "Ed25519Signature2020");
  assert.ok(credential.proof.proofValue.startsWith("u"));

  const review = await app.request(`/v1/actions/${authorization.actionId}/review`, {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ reason: "Refund exceeds the desk limit" }),
  });
  assert.equal(review.status, 201);
  const reviewBody = (await review.json()) as { id: string; status: string };
  assert.equal(reviewBody.status, "pending");
  assert.equal(
    (await app.request(`/v1/actions/${authorization.actionId}/review`, {
      method: "POST",
      headers: { ...auth, "content-type": "application/json" },
      body: "{}",
    })).status,
    409,
  );
  const pendingReviews = await app.request("/v1/reviews?status=pending", { headers: auth });
  assert.equal(pendingReviews.status, 200);
  const pendingBody = (await pendingReviews.json()) as { items: Array<{ id: string; action_id: string }> };
  assert.ok(pendingBody.items.some((item) => item.id === reviewBody.id && item.action_id === authorization.actionId));
  assert.equal((await app.request("/v1/reviews?status=nope", { headers: auth })).status, 400);
  const decided = await app.request(`/v1/reviews/${reviewBody.id}/decision`, {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve", note: "Verified with the customer" }),
  });
  assert.equal(decided.status, 200);
  assert.equal(((await decided.json()) as { status: string }).status, "approved");
  assert.equal(
    (await app.request(`/v1/reviews/${reviewBody.id}/decision`, {
      method: "POST",
      headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify({ decision: "reject" }),
    })).status,
    404,
  );
  const approvedReviews = await app.request("/v1/reviews?status=approved", { headers: auth });
  assert.equal(approvedReviews.status, 200);
  assert.ok(
    ((await approvedReviews.json()) as { items: Array<{ id: string }> }).items.some(
      (item) => item.id === reviewBody.id,
    ),
  );
  const detailWithReview = await app.request(`/v1/actions/${authorization.actionId}`, { headers: auth });
  assert.equal(detailWithReview.status, 200);
  assert.equal(
    ((await detailWithReview.json()) as { review: { status: string } }).review.status,
    "approved",
  );

  const transitions = await app.request("/v1/transitions", { headers: auth });
  assert.equal(transitions.status, 200);
  assert.equal((await transitions.json()).items.length, 1);
  const stepped = await app.request("/v1/transitions", {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ type: "authority.stepped_up", target: "billing-agent" }),
  });
  assert.equal(stepped.status, 201);

  assert.equal((await app.request("/v1/agents", { headers: auth })).status, 200);
  assert.equal((await app.request("/v1/usage", { headers: auth })).status, 200);
  assert.equal((await app.request("/v1/audit", { headers: auth })).status, 200);

  const policy = await app.request("/v1/policies/test-policy", {
    method: "PUT",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ allow: ["stripe:refunds.create"] }),
  });
  assert.equal(policy.status, 200);
  assert.equal((await app.request("/v1/policies", { headers: auth })).status, 200);
  assert.equal((await app.request("/v1/policies/test-policy", { headers: auth })).status, 200);
  assert.equal((await app.request("/v1/policies/test-policy", { method: "DELETE", headers: auth })).status, 200);
  assert.equal((await app.request("/v1/policies/propose", { headers: auth })).status, 200);

  assert.equal((await app.request("/v1/evidence/readiness", { headers: auth })).status, 200);
  assert.equal(
    (await app.request("/v1/evidence-packs", {
      method: "POST",
      headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify({ since: "2026-12-01", until: "2026-01-01" }),
    })).status,
    400,
  );
  const pack = await app.request("/v1/evidence-packs", {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({
      frameworks: ["soc2", "dora"],
      since: "2026-01-01",
      until: "2026-12-31",
      recipients: ["reviewer@example.com"],
    }),
  });
  assert.equal(pack.status, 201);
  const packBody = (await pack.json()) as {
    id: string;
    summary: {
      version: number;
      frameworks: unknown[];
      records: unknown[];
      recipients: string[];
    };
  };
  assert.equal(packBody.summary.version, 1);
  assert.equal(packBody.summary.frameworks.length, 2);
  assert.ok(packBody.summary.records.length >= 1);
  assert.deepEqual(packBody.summary.recipients, ["reviewer@example.com"]);
  assert.equal((await app.request("/v1/evidence-packs", { headers: auth })).status, 200);
  const packDetail = await app.request(`/v1/evidence-packs/${packBody.id}`, { headers: auth });
  assert.equal(packDetail.status, 200);
  assert.equal(((await packDetail.json()) as { summary: { version: number } }).summary.version, 1);
  const download = await app.request(`/v1/evidence-packs/${packBody.id}/download`, { headers: auth });
  assert.equal(download.status, 200);
  const report = await app.request(`/v1/evidence-packs/${packBody.id}/report`, { headers: auth });
  assert.equal(report.status, 200);
  assert.match(report.headers.get("content-type") ?? "", /text\/html/);
  assert.match(await report.text(), /Evidence pack/);
  const share = await app.request(`/v1/evidence-packs/${packBody.id}/share`, {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ expiresInDays: 7 }),
  });
  assert.equal(share.status, 200);
  const shareUrl = ((await share.json()) as { url: string }).url;
  const shareToken = shareUrl.split("/").pop()!;
  assert.equal((await app.request(`/v1/public/evidence/${shareToken}`)).status, 200);
  assert.equal((await app.request(`/v1/public/evidence/${shareToken}/download`)).status, 200);
  assert.equal((await app.request(`/v1/public/evidence/${shareToken}/report`)).status, 200);
  assert.equal(
    (await app.request(`/v1/evidence-packs/${packBody.id}/share`, { method: "DELETE", headers: auth })).status,
    200,
  );
  assert.equal((await app.request(`/v1/public/evidence/${shareToken}`)).status, 404);

  const billing = await app.request("/v1/billing", { headers: auth });
  assert.equal(billing.status, 200);
  assert.equal(
    (await app.request("/v1/billing/checkout", {
      method: "POST",
      headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify({ plan: "team" }),
    })).status,
    503,
  );
  assert.equal(
    (await app.request("/v1/billing/portal", { method: "POST", headers: auth })).status,
    503,
  );

  const webhook = await app.request("/v1/webhooks", {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ url: "https://example.com/tessera-hook", events: ["action.completed"] }),
  });
  assert.equal(webhook.status, 201);
  const webhookBody = (await webhook.json()) as { id: string };
  assert.equal((await app.request("/v1/webhooks", { headers: auth })).status, 200);
  assert.equal((await app.request("/v1/webhook-events", { headers: auth })).status, 200);
  assert.equal((await app.request("/v1/webhook-deliveries", { headers: auth })).status, 200);
  assert.equal((await app.request(`/v1/webhooks/${webhookBody.id}`, { method: "DELETE", headers: auth })).status, 200);

  const link = await app.request("/v1/verification-links", {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ actionId: authorization.actionId }),
  });
  assert.equal(link.status, 201);
  const linkBody = (await link.json()) as { id: string; url: string };
  assert.equal((await app.request("/v1/verification-links", { headers: auth })).status, 200);
  const token = linkBody.url.split("/").pop()!;
  assert.equal((await app.request(`/v1/public/verify/${token}`)).status, 200);
  assert.equal((await app.request(`/v1/verification-links/${linkBody.id}`, { method: "DELETE", headers: auth })).status, 200);

  assert.equal(
    (await app.request(`/v1/agent-keys/${key.id}`, { method: "DELETE", headers: auth })).status,
    200,
  );
  assert.equal((await app.request(`/v1/environments/${environment.id}`, { method: "DELETE", headers: auth })).status, 200);
  assert.equal((await app.request("/auth/logout", { method: "POST", headers: auth })).status, 200);
  await closeDb();
});

after(async () => {
  broker.close();
  const { closeDb } = await import("../src/db.js");
  await closeDb().catch(() => {});
  await rm(evidenceDir, { recursive: true, force: true });
});
