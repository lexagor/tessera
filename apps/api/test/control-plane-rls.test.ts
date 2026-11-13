import assert from "node:assert/strict";
import { test } from "node:test";

const databaseUrl = process.env.TEST_DATABASE_URL;
process.env.NODE_ENV = "test";
process.env.DATABASE_URL = databaseUrl ?? "postgres://unused";
process.env.CONTROL_PLANE_RLS = "1";
process.env.PUBLIC_BASE_URL = "http://localhost:5173";
process.env.CONTROL_PLANE_ENC_KEY = "11".repeat(32);

const canRun = Boolean(databaseUrl);

test("control-plane RLS scopes tenant queries and preserves an explicit admin path", { skip: !canRun }, async () => {
  const { migrate, db, withAdminContext, withOrgContext, closeDb } = await import("../src/db.js");
  const auth = await import("../src/auth.js");
  await migrate();
  await withAdminContext(async () => {
    await db().unsafe(`
      DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tessera_rls_test') THEN
          CREATE ROLE tessera_rls_test NOLOGIN;
        END IF;
      END $$;
      GRANT USAGE ON SCHEMA public TO tessera_rls_test;
      GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO tessera_rls_test;
    `);
  });

  const suffix = Date.now();
  const { user: userA, org: orgA } = await withAdminContext(async () => {
    const user = await auth.findOrCreateUser({ email: `rls-a-${suffix}@example.com`, name: "RLS A" });
    const org = await auth.createOrgForUser(user, "RLS A Workspace");
    return { user, org };
  });
  const { org: orgB } = await withAdminContext(async () => {
    const user = await auth.findOrCreateUser({ email: `rls-b-${suffix}@example.com`, name: "RLS B" });
    const org = await auth.createOrgForUser(user, "RLS B Workspace");
    return { user, org };
  });

  const tenantA = await withOrgContext(orgA.id, async () => {
    await db().unsafe("SET LOCAL ROLE tessera_rls_test");
    const rows = await db()`SELECT id FROM orgs WHERE id = ${orgB.id}`;
    return rows.length;
  });
  assert.equal(tenantA, 0, "tenant A cannot see tenant B's org");

  const admin = await withAdminContext(async () => {
    const rows = await db()`SELECT id FROM orgs WHERE id IN (${orgA.id}, ${orgB.id})`;
    return rows.length;
  });
  assert.equal(admin, 2, "admin context sees both orgs");

  // The org-scoped transaction sees its own row.
  const own = await withOrgContext(orgA.id, async () => {
    await db().unsafe("SET LOCAL ROLE tessera_rls_test");
    const rows = await db()`SELECT id FROM orgs WHERE id = ${orgA.id}`;
    return rows.length;
  });
  assert.equal(own, 1);

  await closeDb();
});
