import assert from "node:assert/strict";
import { test } from "node:test";

process.env.NODE_ENV = "test";
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? "postgres://unused";
process.env.ALLOW_PRIVATE_WEBHOOKS = "0";

const { safeWebhookPost } = await import("../src/safe-webhook.js");

test("safe webhook POST rejects private hosts when private webhooks are disabled", async () => {
  await assert.rejects(
    safeWebhookPost({
      url: "http://127.0.0.1:9/hook",
      headers: { "content-type": "application/json" },
      body: "{}",
    }),
    /Private webhook hosts are not allowed/,
  );
  await assert.rejects(
    safeWebhookPost({
      url: "http://localhost:9/hook",
      headers: { "content-type": "application/json" },
      body: "{}",
    }),
    /Private webhook hosts are not allowed/,
  );
});
