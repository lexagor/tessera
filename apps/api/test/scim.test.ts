import assert from "node:assert/strict";
import { test } from "node:test";

const databaseUrl = process.env.TEST_DATABASE_URL;
process.env.NODE_ENV = "test";
process.env.DATABASE_URL = databaseUrl ?? "postgres://unused";
process.env.AUTH_DEV_MODE = "1";
process.env.BROKER_DEMO_ALLOW = "1";
process.env.PUBLIC_BASE_URL = "http://localhost:5173";
process.env.CONTROL_PLANE_ENC_KEY = "11".repeat(32);

const canRun = Boolean(databaseUrl);

test("SCIM users are org-scoped, provisionable, and revocable", { skip: !canRun }, async () => {
  const { migrate, closeDb } = await import("../src/db.js");
  await migrate();
  const { app } = await import("../src/index.js");
  const auth = await import("../src/auth.js");

  const user = await auth.findOrCreateUser({
    email: `scim-${Date.now()}@example.com`,
    name: "SCIM Admin",
  });
  const org = await auth.createOrgForUser(user, "SCIM Test Workspace");
  const session = await auth.createSession(user.id, org.id);
  const cookie = `tessera_session=${session.token}`;

  const tokenResponse = await app.request("/v1/scim-tokens", {
    method: "POST",
    headers: { ...{ cookie }, "content-type": "application/json" },
    body: JSON.stringify({ name: "Test IdP" }),
  });
  assert.equal(tokenResponse.status, 201);
  const tokenBody = (await tokenResponse.json()) as { id: string; token: string };
  assert.match(tokenBody.token, /^scim_/);

  const bearer = { authorization: `Bearer ${tokenBody.token}` };
  const list = await app.request("/scim/v2/Users", { headers: bearer });
  assert.equal(list.status, 200);
  assert.equal(((await list.json()) as { totalResults: number }).totalResults, 1);

  const created = await app.request("/scim/v2/Users", {
    method: "POST",
    headers: { ...bearer, "content-type": "application/scim+json" },
    body: JSON.stringify({
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
      userName: `provisioned-${Date.now()}@example.com`,
      name: { formatted: "Provisioned User" },
      roles: [{ value: "admin" }],
      active: true,
    }),
  });
  assert.equal(created.status, 201);
  const createdUser = (await created.json()) as { id: string; userName: string; active: boolean };
  assert.equal(createdUser.active, true);

  const group = await app.request("/scim/v2/Groups", {
    method: "POST",
    headers: { ...bearer, "content-type": "application/scim+json" },
    body: JSON.stringify({
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
      displayName: `proof-admins-${Date.now()}`,
      members: [{ value: createdUser.id }],
      "urn:tessera:params:scim:schemas:extension:2.0:Group": { role: "admin" },
    }),
  });
  assert.equal(group.status, 201);
  const groupBody = (await group.json()) as { id: string; members: Array<{ value: string }> };
  assert.equal(groupBody.members[0]?.value, createdUser.id);
  const groups = await app.request("/scim/v2/Groups", { headers: bearer });
  assert.equal(groups.status, 200);
  assert.equal(((await groups.json()) as { totalResults: number }).totalResults, 1);
  const groupPatch = await app.request(`/scim/v2/Groups/${groupBody.id}`, {
    method: "PATCH",
    headers: { ...bearer, "content-type": "application/scim+json" },
    body: JSON.stringify({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [{ op: "replace", path: "members", value: [] }],
    }),
  });
  assert.equal(groupPatch.status, 200);
  assert.equal((await app.request(`/scim/v2/Groups/${groupBody.id}`, { method: "DELETE", headers: bearer })).status, 204);

  const patched = await app.request(`/scim/v2/Users/${createdUser.id}`, {
    method: "PATCH",
    headers: { ...bearer, "content-type": "application/scim+json" },
    body: JSON.stringify({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [{ op: "replace", path: "active", value: false }],
    }),
  });
  assert.equal(patched.status, 200);
  assert.equal(((await patched.json()) as { active: boolean }).active, false);

  const removed = await app.request(`/scim/v2/Users/${createdUser.id}`, { headers: bearer });
  assert.equal(removed.status, 404);

  const revoke = await app.request(`/v1/scim-tokens/${tokenBody.id}`, {
    method: "DELETE",
    headers: { cookie },
  });
  assert.equal(revoke.status, 200);
  const denied = await app.request("/scim/v2/Users", { headers: bearer });
  assert.equal(denied.status, 401);

  await closeDb();
});
