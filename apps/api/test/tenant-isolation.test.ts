import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

const databaseUrl = process.env.TEST_DATABASE_URL;
const evidenceDir = await mkdtemp(join(tmpdir(), "tessera-tenant-test-"));

function json(res: ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
}

const mockBroker = createServer((req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname === "/v1/policies" && req.method === "GET") {
    return json(res, 200, { items: [] });
  }
  if (url.pathname === "/v1/key-events") {
    return json(res, 200, { items: [], verified: true, signaturesValid: true });
  }
  if (url.pathname === "/v1/integrity") {
    return json(res, 200, {
      chains: { agents: 0, receipts: 0, verified: true, unanchoredAgents: 0, drift: [] },
      anchors: { count: 0, latest: null, pending: 0 },
      keyEvents: { count: 0, verified: true, signaturesValid: true, chainValid: true },
    });
  }
  return json(res, 404, { error: `mock broker has no ${req.method} ${url.pathname}` });
});

const brokerPort = await new Promise<number>((resolve, reject) => {
  mockBroker.once("error", reject);
  mockBroker.listen(0, "127.0.0.1", () => {
    const address = mockBroker.address();
    if (!address || typeof address === "string") return reject(new Error("no broker port"));
    resolve(address.port);
  });
});

process.env.NODE_ENV = "test";
process.env.DATABASE_URL = databaseUrl ?? "postgres://unused";
process.env.BROKER_URL = `http://127.0.0.1:${brokerPort}`;
process.env.BROKER_DEMO_ALLOW = "1";
process.env.PUBLIC_BASE_URL = "http://localhost:5173";
process.env.CONTROL_PLANE_ENC_KEY = "11".repeat(32);
process.env.AGENT_RECEIPT_ED25519_KEY = `0x${"42".repeat(32)}`;
process.env.AGENT_RECEIPT_ISSUER_DID = "did:web:api.test";
process.env.EVIDENCE_DIR = evidenceDir;

const canRun = Boolean(databaseUrl);

test("control plane tenant isolation: A cannot read or mutate B", { skip: !canRun }, async () => {
  const { migrate, closeDb, db } = await import("../src/db.js");
  await migrate();
  const { app } = await import("../src/index.js");
  const { findOrCreateUser, createOrgForUser, createSession } = await import("../src/auth.js");
  const { newAgentKey, sha256, uuid } = await import("../src/crypto.js");
  const { audit } = await import("../src/audit.js");

  const stamp = Date.now();
  const userA = await findOrCreateUser({ email: `tenant-a-${stamp}@example.com`, name: "Tenant A" });
  const userB = await findOrCreateUser({ email: `tenant-b-${stamp}@example.com`, name: "Tenant B" });
  const orgA = await createOrgForUser(userA, `Tenant A ${stamp}`);
  const orgB = await createOrgForUser(userB, `Tenant B ${stamp}`);
  const sessionA = await createSession(userA.id, orgA.id);
  const authA = { cookie: `tessera_session=${sessionA.token}` };

  const envA = await app.request("/v1/environments", {
    method: "POST",
    headers: { ...authA, "content-type": "application/json" },
    body: JSON.stringify({ name: "Tenant A Production" }),
  });
  assert.equal(envA.status, 201);
  const environmentA = (await envA.json()) as { id: string; name: string };

  // The helper is only used for a second environment in Tenant A, not for Tenant B.
  const sessionB = await createSession(userB.id, orgB.id);
  const envB = await app.request("/v1/environments", {
    method: "POST",
    headers: {
      cookie: `tessera_session=${sessionB.token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ name: "Tenant B Production" }),
  });
  assert.equal(envB.status, 201);
  const environmentB = (await envB.json()) as { id: string; name: string };

  const actionA = uuid();
  const actionB = uuid();
  const insertAction = async (orgId: string, environmentId: string, actionIdValue: string, agent: string) => {
    await db()`
      INSERT INTO actions (
        action_id, org_id, environment_id, agent_id, principal_id, tool, decision,
        outcome_status, policy_id, policy_version, policy_hash, credential_issuer,
        credential_thumbprint, receipt_id, outcome_receipt_id, created_at, completed_at,
        verified, payload
      ) VALUES (
        ${actionIdValue}, ${orgId}, ${environmentId}, ${agent}, ${`${agent}-principal`},
        'stripe.refunds.create', 'allow', 'success', 'tenant-test-policy', 1,
        ${`0x${"11".repeat(32)}`}, NULL, NULL, ${`0x${"22".repeat(32)}`}, NULL,
        now(), now(), true, ${db().json({ authorization: null, outcome: null } as never)}
      )
    `;
  };
  await insertAction(orgA.id, environmentA.id, actionA, "tenant-a-agent");
  await insertAction(orgB.id, environmentB.id, actionB, "tenant-b-agent");

  const reviewB = uuid();
  await db()`
    INSERT INTO action_reviews (id, org_id, environment_id, action_id, status, reason, requested_by)
    VALUES (${reviewB}, ${orgB.id}, ${environmentB.id}, ${actionB}, 'pending', 'B only', ${userB.id})
  `;
  const packB = uuid();
  await db()`
    INSERT INTO evidence_packs (id, org_id, environment_id, status, filters, summary, created_by)
    VALUES (${packB}, ${orgB.id}, ${environmentB.id}, 'ready', ${db().json({} as never)}, ${db().json({} as never)}, ${userB.id})
  `;
  const linkB = uuid();
  await db()`
    INSERT INTO verification_links (id, org_id, environment_id, action_id, token_hash, expires_at, created_by)
    VALUES (${linkB}, ${orgB.id}, ${environmentB.id}, ${actionB}, ${sha256(`link-${stamp}`)}, now() + interval '1 day', ${userB.id})
  `;
  const key = newAgentKey();
  const agentKeyB = uuid();
  const integrationB = uuid();
  await db()`
    INSERT INTO agent_keys (id, environment_id, name, prefix, key_hash, expires_at)
    VALUES (${agentKeyB}, ${environmentB.id}, 'B key', ${key.prefix}, ${key.hash}, now() + interval '30 days')
  `;
  await db()`
    INSERT INTO integration_connections (
      id, org_id, environment_id, provider, name, status, auth_mode, scopes,
      owner_user_id, metadata, created_at, updated_at
    ) VALUES (
      ${integrationB}, ${orgB.id}, ${environmentB.id}, 'slack', 'Tenant B Slack',
      'needs_attention', 'api_key', ${db().json(["chat"] as never)}, ${userB.id},
      ${db().json({} as never)}, now(), now()
    )
  `;
  await audit({
    orgId: orgB.id,
    actorUserId: userB.id,
    action: "tenant-b-only",
    target: "tenant-b-target",
    details: {},
  });

  const me = await app.request("/v1/me", { headers: authA });
  assert.equal(me.status, 200);
  const meBody = (await me.json()) as { environments: Array<{ id: string }> };
  assert.ok(meBody.environments.some((item) => item.id === environmentA.id));
  assert.equal(meBody.environments.some((item) => item.id === environmentB.id), false);

  const actionsB = await app.request(`/v1/actions?environmentId=${environmentB.id}`, { headers: authA });
  assert.equal(actionsB.status, 200);
  assert.deepEqual((await actionsB.json()).items, []);
  assert.equal((await app.request(`/v1/actions/${actionB}`, { headers: authA })).status, 404);
  assert.equal((await app.request(`/v1/actions/${actionB}/agent-receipt`, { headers: authA })).status, 404);

  const agentsB = await app.request(`/v1/agents?environmentId=${environmentB.id}`, { headers: authA });
  assert.equal(agentsB.status, 200);
  assert.deepEqual((await agentsB.json()).items, []);

  const keysB = await app.request(`/v1/agent-keys?environmentId=${environmentB.id}`, { headers: authA });
  assert.equal(keysB.status, 404);
  const keysA = await app.request("/v1/agent-keys", { headers: authA });
  assert.equal(keysA.status, 200);
  assert.deepEqual((await keysA.json()).items, []);
  const revokeKey = await app.request(`/v1/agent-keys/${agentKeyB}`, { method: "DELETE", headers: authA });
  assert.equal(revokeKey.status, 200);
  assert.equal(((await revokeKey.json()) as { revoked: boolean }).revoked, false);

  const reviewsB = await app.request("/v1/reviews?status=all", { headers: authA });
  assert.equal(reviewsB.status, 200);
  assert.equal(((await reviewsB.json()) as { items: Array<{ id: string }> }).items.some((item) => item.id === reviewB), false);
  assert.equal(
    (await app.request(`/v1/reviews/${reviewB}/decision`, {
      method: "POST",
      headers: { ...authA, "content-type": "application/json" },
      body: JSON.stringify({ decision: "approve" }),
    })).status,
    404,
  );

  const packsB = await app.request(`/v1/evidence-packs?environmentId=${environmentB.id}`, { headers: authA });
  assert.equal(packsB.status, 200);
  assert.deepEqual((await packsB.json()).items, []);
  assert.equal((await app.request(`/v1/evidence-packs/${packB}`, { headers: authA })).status, 404);
  assert.equal((await app.request(`/v1/evidence-packs/${packB}/download`, { headers: authA })).status, 404);
  assert.equal((await app.request(`/v1/evidence-packs/${packB}/report`, { headers: authA })).status, 404);
  assert.equal((await app.request(`/v1/evidence-packs/${packB}/share`, { method: "POST", headers: authA })).status, 404);

  const linksB = await app.request("/v1/verification-links", { headers: authA });
  assert.equal(linksB.status, 200);
  assert.equal(((await linksB.json()) as { items: Array<{ id: string }> }).items.some((item) => item.id === linkB), false);
  assert.equal(
    (await app.request("/v1/verification-links", {
      method: "POST",
      headers: { ...authA, "content-type": "application/json" },
      body: JSON.stringify({ actionId: actionB }),
    })).status,
    404,
  );
  const revokeLink = await app.request(`/v1/verification-links/${linkB}`, { method: "DELETE", headers: authA });
  assert.equal(revokeLink.status, 200);
  assert.equal(((await revokeLink.json()) as { revoked: boolean }).revoked, false);

  const integrationsB = await app.request(`/v1/integrations?environmentId=${environmentB.id}`, { headers: authA });
  assert.equal(integrationsB.status, 200);
  assert.deepEqual((await integrationsB.json()).items, []);
  assert.equal(
    (await app.request(`/v1/integrations/${integrationB}/test?environmentId=${environmentB.id}`, {
      method: "POST",
      headers: authA,
    })).status,
    404,
  );
  assert.equal(
    (await app.request(`/v1/integrations/${integrationB}/rotate?environmentId=${environmentB.id}`, {
      method: "POST",
      headers: { ...authA, "content-type": "application/json" },
      body: JSON.stringify({ credential: { token: "x" } }),
    })).status,
    404,
  );

  assert.equal((await app.request(`/v1/analytics?environmentId=${environmentB.id}`, { headers: authA })).status, 404);
  const notificationsB = await app.request(`/v1/notifications?environmentId=${environmentB.id}`, { headers: authA });
  assert.equal(notificationsB.status, 200);
  assert.deepEqual((await notificationsB.json()).items, []);
  assert.equal((await app.request(`/v1/search?environmentId=${environmentB.id}&q=${encodeURIComponent("tenant-b")}`, { headers: authA })).status, 200);
  const transitionB = await app.request(`/v1/transitions?environmentId=${environmentB.id}`, { headers: authA });
  assert.equal(transitionB.status, 200);
  assert.deepEqual((await transitionB.json()).items, []);
  const auditB = await app.request("/v1/audit", { headers: authA });
  assert.equal(auditB.status, 200);
  assert.equal(
    ((await auditB.json()) as { items: Array<{ action: string }> }).items.some((item) => item.action === "tenant-b-only"),
    false,
  );

  // Tenant B can still read its own data.
  const authB = { cookie: `tessera_session=${sessionB.token}` };
  assert.equal((await app.request(`/v1/actions/${actionB}`, { headers: authB })).status, 200);
  assert.equal((await app.request(`/v1/evidence-packs/${packB}`, { headers: authB })).status, 200);
  assert.equal((await app.request(`/v1/reviews/${reviewB}/decision`, {
    method: "POST",
    headers: { ...authB, "content-type": "application/json" },
    body: JSON.stringify({ decision: "reject", note: "B own review" }),
  })).status, 200);

  await closeDb();
});

after(async () => {
  mockBroker.close();
  const { closeDb } = await import("../src/db.js");
  await closeDb().catch(() => {});
  await rm(evidenceDir, { recursive: true, force: true });
});
