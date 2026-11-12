import assert from "node:assert/strict";
import { createServer } from "node:http";
import { after, test } from "node:test";

const databaseUrl = process.env.TEST_DATABASE_URL;

process.env.NODE_ENV = "test";
process.env.DATABASE_URL = databaseUrl ?? "postgres://unused";
process.env.ALLOW_PRIVATE_WEBHOOKS = "1";
process.env.CONTROL_PLANE_ENC_KEY = "11".repeat(32);

let delivered = 0;
const receiver = createServer((req, res) => {
  delivered += 1;
  req.resume();
  req.on("end", () => {
    res.statusCode = 204;
    res.end();
  });
});

const port = await new Promise<number>((resolve, reject) => {
  receiver.once("error", reject);
  receiver.listen(0, "127.0.0.1", () => {
    const address = receiver.address();
    if (!address || typeof address === "string") return reject(new Error("no port"));
    resolve(address.port);
  });
});

after(async () => {
  const { closeDb } = await import("../src/db.js");
  await new Promise<void>((resolve) => receiver.close(() => resolve()));
  await closeDb().catch(() => {});
});

test("webhook deliveries are claimed and marked delivered", { skip: !databaseUrl }, async () => {
  const { migrate, db } = await import("../src/db.js");
  await migrate();
  const { createWebhookEndpoint, processWebhookDeliveries } = await import("../src/webhooks.js");
  const { findOrCreateUser, createOrgForUser } = await import("../src/auth.js");
  const { uuid } = await import("../src/crypto.js");

  const stamp = Date.now();
  const user = await findOrCreateUser({ email: `webhook-${stamp}@example.com`, name: "Webhook" });
  const org = await createOrgForUser(user, `Webhook ${stamp}`);
  const endpoint = await createWebhookEndpoint({
    orgId: org.id,
    url: `http://127.0.0.1:${port}/hook`,
    events: ["*"],
  });
  await db()`
    INSERT INTO webhook_deliveries (id, endpoint_id, org_id, event, payload)
    VALUES (
      ${uuid()},
      ${endpoint.id},
      ${org.id},
      'action.completed',
      ${db().json({ event: "action.completed", data: { actionId: "a1" } } as never)}
    )
  `;

  await Promise.all([processWebhookDeliveries(), processWebhookDeliveries()]);
  assert.equal(delivered, 1);
  const rows = await db()`
    SELECT status, attempts, locked_by FROM webhook_deliveries WHERE endpoint_id = ${endpoint.id}
  `;
  assert.equal(rows[0]?.status, "delivered");
  assert.equal(Number(rows[0]?.attempts), 1);
  assert.equal(rows[0]?.locked_by, null);

  await db()`DELETE FROM orgs WHERE id = ${org.id}`;
});
