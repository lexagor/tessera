import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

const databaseUrl = process.env.TEST_DATABASE_URL;
const evidenceDir = await mkdtemp(join(tmpdir(), "tessera-authority-test-"));
const authoritySecret = "tessera-test-authority-secret-32-bytes-minimum";

let lastAuthorizeBody: Record<string, any> | null = null;
let actionCounter = 0;

function json(res: ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
}

async function readBody(req: IncomingMessage): Promise<Record<string, any>> {
  let raw = "";
  for await (const chunk of req) raw += chunk;
  return raw ? (JSON.parse(raw) as Record<string, any>) : {};
}

const broker = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname === "/healthz") return json(res, 200, { status: "ok" });
  if (url.pathname === "/v1/authorize") {
    const body = await readBody(req);
    lastAuthorizeBody = body;
    const actionId = `authority-action-${Date.now()}-${actionCounter++}`;
    const hash = `0x${"aa".repeat(32)}`;
    return json(res, 200, {
      decision: "allow",
      reason: "test",
      actionId,
      receiptId: hash,
      credential: null,
      receipt: {
        actionId,
        agent: body.agentId,
        user: body.userId,
        principal: {
          principalId: body.userId,
          principalType: "user",
          authorityRef: "test-authority",
          authorityHash: hash,
          verificationMethod: "hmac-jwt",
        },
        call: { tool: body.tool, argsHash: hash },
        authorization: { decision: "allow", policy: "test-policy", reasonCode: "ALLOW" },
        policy: { policyId: "test-policy", policyVersion: 1, policyHash: hash },
        credential: { issuer: "stripe", thumbprint: hash },
        ts: new Date().toISOString(),
      },
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
process.env.VERIFY_BASE_URL = "https://verify.thetessera.xyz";
process.env.CONTROL_PLANE_ENC_KEY = "11".repeat(32);
process.env.TESSERA_AUTHORITY_HMAC_SECRET = authoritySecret;
process.env.TESSERA_AUTHORITY_TOKEN_TTL_SECONDS = "120";
process.env.EVIDENCE_DIR = evidenceDir;

const canRun = Boolean(databaseUrl);

after(async () => {
  await new Promise<void>((resolve) => broker.close(() => resolve()));
});

test("human authority: owner-bound and per-call tokens reach the broker", { skip: !canRun }, async () => {
  const { migrate, closeDb, db } = await import("../src/db.js");
  await migrate();
  const { app } = await import("../src/index.js");
  const authModule = await import("../src/auth.js");
  const { verifyAuthorityToken } = await import("../src/authority.js");

  const user = await authModule.findOrCreateUser({
    email: `authority-${Date.now()}@example.com`,
    name: "Authority Test",
    subject: `oidc-${Date.now()}`,
  });
  const org = await authModule.createOrgForUser(user, "Authority Test Workspace");
  const session = await authModule.createSession(user.id, org.id);
  const auth = { cookie: `tessera_session=${session.token}` };

  const envCreated = await app.request("/v1/environments", {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ name: `authority-${Date.now()}` }),
  });
  assert.equal(envCreated.status, 201);
  const environment = (await envCreated.json()) as { id: string };

  const ownerKeyCreated = await app.request("/v1/agent-keys", {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ name: "owner-bound" }),
  });
  assert.equal(ownerKeyCreated.status, 201);
  const ownerKey = (await ownerKeyCreated.json()) as {
    id: string;
    key: string;
    delegationMode: string;
    delegatedTo: string;
  };
  assert.equal(ownerKey.delegationMode, "owner");
  assert.equal(ownerKey.delegatedTo, user.email);

  const keyList = await app.request("/v1/agent-keys", { headers: auth });
  const listed = (await keyList.json()) as {
    items: Array<{ delegation_mode: string; delegated_email: string | null }>;
  };
  assert.equal(listed.items[0]?.delegation_mode, "owner");
  assert.equal(listed.items[0]?.delegated_email, user.email);

  const ownerAuthorize = await app.request("/v1/authorize", {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": ownerKey.key },
    body: JSON.stringify({
      agentId: "authority-agent",
      userId: "caller-supplied-user",
      tool: "stripe.refunds.create",
      intent: "refund a duplicate charge",
      args: { charge: "ch_1" },
    }),
  });
  assert.equal(ownerAuthorize.status, 200);
  assert.ok(lastAuthorizeBody?.authorityToken);
  assert.equal(lastAuthorizeBody?.userId, user.id);
  const ownerClaims = verifyAuthorityToken(lastAuthorizeBody!.authorityToken, {
    orgId: org.id,
    environmentId: environment.id,
    agentId: "authority-agent",
  });
  assert.equal(ownerClaims.sub, user.id);
  assert.equal(ownerClaims.authority_ref, `oidc:${user.oidc_subject}`);
  assert.equal(ownerClaims.environment_id, environment.id);

  const tokenKeyCreated = await app.request("/v1/agent-keys", {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ name: "per-call", delegationMode: "token" }),
  });
  assert.equal(tokenKeyCreated.status, 201);
  const tokenKey = (await tokenKeyCreated.json()) as { key: string };

  const missingToken = await app.request("/v1/authorize", {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": tokenKey.key },
    body: JSON.stringify({
      agentId: "authority-agent",
      userId: "caller-supplied-user",
      tool: "stripe.refunds.create",
      intent: "refund",
      args: {},
    }),
  });
  assert.equal(missingToken.status, 400);

  const tokenResponse = await app.request("/v1/authority-tokens", {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ agentId: "authority-agent", ttlSeconds: 60 }),
  });
  assert.equal(tokenResponse.status, 200);
  const minted = (await tokenResponse.json()) as { token: string; expiresAt: string };
  assert.ok(minted.token);
  assert.ok(minted.expiresAt);

  const wrongAgentAuthorize = await app.request("/v1/authorize", {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": tokenKey.key },
    body: JSON.stringify({
      agentId: "other-agent",
      userId: user.id,
      tool: "stripe.refunds.create",
      intent: "refund",
      args: {},
      authorityToken: minted.token,
    }),
  });
  assert.equal(wrongAgentAuthorize.status, 401);

  const perCallAuthorize = await app.request("/v1/authorize", {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": tokenKey.key },
    body: JSON.stringify({
      agentId: "authority-agent",
      userId: user.id,
      tool: "stripe.refunds.create",
      intent: "refund",
      args: {},
      authorityToken: minted.token,
    }),
  });
  assert.equal(perCallAuthorize.status, 200);
  assert.equal(lastAuthorizeBody?.authorityToken, minted.token);

  const callerKeyCreated = await app.request("/v1/agent-keys", {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ name: "caller", delegationMode: "caller" }),
  });
  assert.equal(callerKeyCreated.status, 201);
  const callerKey = (await callerKeyCreated.json()) as { key: string };
  const callerAuthorize = await app.request("/v1/authorize", {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": callerKey.key },
    body: JSON.stringify({
      agentId: "authority-agent",
      userId: "caller-supplied-user",
      tool: "stripe.refunds.create",
      intent: "refund",
      args: {},
    }),
  });
  assert.equal(callerAuthorize.status, 200);
  assert.equal(lastAuthorizeBody?.authorityToken, undefined);

  const ownerWithToken = await app.request("/v1/authorize", {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": ownerKey.key },
    body: JSON.stringify({
      agentId: "authority-agent",
      userId: user.id,
      tool: "stripe.refunds.create",
      intent: "refund",
      args: {},
      authorityToken: minted.token,
    }),
  });
  assert.equal(ownerWithToken.status, 400);

  await db()`DELETE FROM orgs WHERE id = ${org.id}`;
  await maybeCloseDb(closeDb);
});

async function maybeCloseDb(closeDb: () => Promise<void>): Promise<void> {
  await closeDb();
}
