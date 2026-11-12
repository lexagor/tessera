import assert from "node:assert/strict";
import { createServer } from "node:http";
import { after, test } from "node:test";

process.env.NODE_ENV = "test";
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? "postgres://unused";
process.env.ALLOW_PRIVATE_WEBHOOKS = "1";

const { isPrivateAddress, isPrivateHostname, safeWebhookPost } = await import(
  "../src/safe-webhook.js"
);

const server = createServer((req, res) => {
  if (req.url === "/redirect") {
    res.statusCode = 302;
    res.setHeader("location", "http://127.0.0.1:1/private");
    res.end();
    return;
  }
  res.statusCode = 200;
  res.end("ok");
});

const port = await new Promise<number>((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", () => {
    const address = server.address();
    if (!address || typeof address === "string") return reject(new Error("no port"));
    resolve(address.port);
  });
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

test("private and reserved addresses are rejected", () => {
  for (const address of [
    "127.0.0.1",
    "10.0.0.1",
    "172.16.4.2",
    "192.168.1.1",
    "169.254.169.254",
    "::1",
    "fe80::1",
    "fc00::1",
    "::ffff:127.0.0.1",
    "::ffff:7f00:1",
  ]) {
    assert.equal(isPrivateAddress(address), true, address);
  }
  assert.equal(isPrivateAddress("8.8.8.8"), false);
  assert.equal(isPrivateHostname("localhost"), true);
  assert.equal(isPrivateHostname("db.internal"), true);
  assert.equal(isPrivateHostname("example.com"), false);
});

test("safe webhook POST succeeds without following redirects", async () => {
  const ok = await safeWebhookPost({
    url: `http://127.0.0.1:${port}/ok`,
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  assert.equal(ok.status, 200);

  await assert.rejects(
    safeWebhookPost({
      url: `http://127.0.0.1:${port}/redirect`,
      headers: { "content-type": "application/json" },
      body: "{}",
    }),
    /redirects are not allowed/,
  );
});
