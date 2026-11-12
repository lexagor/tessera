import assert from "node:assert/strict";
import { test } from "node:test";

process.env.NODE_ENV = "test";
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? "postgres://unused";
process.env.AUTH_DEV_MODE = "1";
process.env.BROKER_DEMO_ALLOW = "1";
process.env.BROKER_URL = "http://127.0.0.1:1";
process.env.PUBLIC_BASE_URL = "http://localhost:5173";
process.env.CONTROL_PLANE_ENC_KEY = "11".repeat(32);
process.env.MAX_REQUEST_BYTES = "1024";
process.env.RATE_LIMIT_TEST = "1";
process.env.RATE_LIMIT_AUTH_PER_MINUTE = "1";

const { app } = await import("../src/index.js");

test("API responses carry security headers and request IDs", async () => {
  const response = await app.request("/healthz", {
    headers: { "x-request-id": "test-request-123" },
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-request-id"), "test-request-123");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(response.headers.get("referrer-policy"), "strict-origin-when-cross-origin");
  assert.equal(response.headers.get("cross-origin-opener-policy"), "same-origin");
  assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);

  const metrics = await app.request("/metrics");
  assert.equal(metrics.status, 200);
  assert.match(await metrics.text(), /tessera_api_requests_total/);
});

test("oversized bodies are rejected before routing", async () => {
  const response = await app.request("/v1/authorize", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ padding: "x".repeat(2_048) }),
  });
  assert.equal(response.status, 413);
  assert.equal(((await response.json()) as { error: { code: string } }).error.code, "payload_too_large");
});

test("auth routes are rate limited per client", async () => {
  const first = await app.request("/auth/login", { redirect: "manual" });
  assert.equal(first.status, 302);
  const second = await app.request("/auth/login", { redirect: "manual" });
  assert.equal(second.status, 429);
  assert.ok(Number(second.headers.get("retry-after")) >= 1);
});
