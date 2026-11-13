import assert from "node:assert/strict";
import { test } from "node:test";

const databaseUrl = process.env.TEST_DATABASE_URL;
process.env.NODE_ENV = "test";
process.env.DATABASE_URL = databaseUrl ?? "postgres://unused";
process.env.CONTROL_PLANE_RLS = "1";
process.env.AUTH_DEV_MODE = "1";
process.env.BROKER_DEMO_ALLOW = "1";
process.env.BROKER_URL = "http://127.0.0.1:1";
process.env.PUBLIC_BASE_URL = "http://localhost:5173";
process.env.CONTROL_PLANE_ENC_KEY = "11".repeat(32);

const canRun = Boolean(databaseUrl);

test("control-plane RLS works through the full API request path", { skip: !canRun }, async () => {
  const { migrate, closeDb } = await import("../src/db.js");
  await migrate();
  const { app } = await import("../src/index.js");

  const login = await app.request("/auth/dev-login", { redirect: "manual" });
  assert.equal(login.status, 302);
  const cookie = login.headers.get("set-cookie")?.split(";")[0];
  assert.ok(cookie);

  const me = await app.request("/v1/me", { headers: { cookie: cookie! } });
  assert.equal(me.status, 200);
  const meBody = (await me.json()) as { org: { id: string }; environments: unknown[] };

  const env = await app.request("/v1/environments", {
    method: "POST",
    headers: { cookie: cookie!, "content-type": "application/json" },
    body: JSON.stringify({ name: `rls-env-${Date.now()}` }),
  });
  assert.equal(env.status, 201);

  const exported = await app.request("/v1/org/export", { headers: { cookie: cookie! } });
  assert.equal(exported.status, 200);
  const exportBody = (await exported.json()) as { scope: { orgId: string } };
  assert.equal(exportBody.scope.orgId, meBody.org.id);

  const scim = await app.request("/v1/scim-tokens", {
    method: "POST",
    headers: { cookie: cookie!, "content-type": "application/json" },
    body: JSON.stringify({ name: "RLS IdP" }),
  });
  assert.equal(scim.status, 201);
  const scimToken = (await scim.json()) as { token: string };
  const scimList = await app.request("/scim/v2/Users", {
    headers: { authorization: `Bearer ${scimToken.token}` },
  });
  assert.equal(scimList.status, 200);

  await closeDb();
});
