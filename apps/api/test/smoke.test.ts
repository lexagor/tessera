import assert from "node:assert/strict";
import { after, test } from "node:test";

const databaseUrl = process.env.TEST_DATABASE_URL;

process.env.NODE_ENV = "test";
process.env.DATABASE_URL = databaseUrl ?? "postgres://unused";
process.env.AUTH_DEV_MODE = "1";
process.env.BROKER_DEMO_ALLOW = "1";
process.env.BROKER_URL = "http://127.0.0.1:1";
process.env.PUBLIC_BASE_URL = "http://localhost:5173";
process.env.SESSION_IDLE_HOURS = "1";
process.env.CONTROL_PLANE_ENC_KEY = "11".repeat(32);

const canRun = Boolean(databaseUrl);

test("control plane smoke: dev login, environment, session", { skip: !canRun }, async () => {
  const { migrate, closeDb } = await import("../src/db.js");
  await migrate();
  const { app } = await import("../src/index.js");

  const health = await app.request("/healthz");
  assert.equal(health.status, 200);

  const config = await app.request("/auth/config");
  assert.equal(config.status, 200);
  assert.equal((await config.json()).devAuth, true);

  const login = await app.request("/auth/dev-login", { redirect: "manual" });
  assert.equal(login.status, 302);
  const cookie = login.headers.get("set-cookie")?.split(";")[0];
  assert.ok(cookie?.startsWith("tessera_session="));

  const me = await app.request("/v1/me", { headers: { cookie: cookie! } });
  assert.equal(me.status, 200);
  const body = (await me.json()) as {
    user: { email: string };
    org: { id: string };
  };
  assert.equal(body.user.email, "dev@tessera.local");

  const { db } = await import("../src/db.js");
  const timeout = await db()`SHOW statement_timeout`;
  assert.equal((timeout[0] as { statement_timeout: string }).statement_timeout, "15s");
  await db()`UPDATE orgs SET plan = 'enterprise' WHERE id = ${body.org.id}`;

  const envName = `test-${Date.now()}`;
  const created = await app.request("/v1/environments", {
    method: "POST",
    headers: { cookie: cookie!, "content-type": "application/json" },
    body: JSON.stringify({ name: envName }),
  });
  assert.equal(created.status, 201);
  const environment = (await created.json()) as { id: string; name: string };
  assert.equal(environment.name, envName);

  const actions = await app.request(`/v1/actions?environmentId=${environment.id}`, {
    headers: { cookie: cookie! },
  });
  assert.equal(actions.status, 200);
  assert.deepEqual((await actions.json()).items, []);

  const billing = await app.request("/v1/billing", { headers: { cookie: cookie! } });
  assert.equal(billing.status, 200);
  const billingBody = (await billing.json()) as { plan: string; usage: { limit: number } };
  assert.ok(billingBody.usage.limit > 0);

  const checkout = await app.request("/v1/billing/checkout", {
    method: "POST",
    headers: { cookie: cookie!, "content-type": "application/json" },
    body: JSON.stringify({ plan: "team" }),
  });
  assert.equal(checkout.status, 503);

  const stripeHook = await app.request("/v1/webhooks/stripe", {
    method: "POST",
    body: "{}",
  });
  assert.equal(stripeHook.status, 503);

  const { sha256 } = await import("../src/crypto.js");
  const token = cookie!.split("=")[1]!;
  await db()`UPDATE sessions SET last_seen_at = now() - interval '2 hours' WHERE token_hash = ${sha256(token)}`;
  const idle = await app.request("/v1/session", { headers: { cookie: cookie! } });
  assert.equal(idle.status, 401);

  await closeDb();
});

after(async () => {
  const { closeDb } = await import("../src/db.js");
  await closeDb().catch(() => {});
});
