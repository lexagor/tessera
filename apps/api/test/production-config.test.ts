import assert from "node:assert/strict";
import { test } from "node:test";

import { productionConfigProblems, type ProductionConfigInput } from "../src/production-config.js";

const valid: ProductionConfigInput = {
  NODE_ENV: "production",
  PUBLIC_BASE_URL: "https://app.thetessera.xyz",
  VERIFY_BASE_URL: "https://verify.thetessera.xyz",
  OIDC_ISSUER: "https://login.example.com",
  OIDC_CLIENT_ID: "client",
  OIDC_CLIENT_SECRET: "secret",
  OIDC_REDIRECT_URI: "https://app.thetessera.xyz/auth/callback",
  OIDC_STATE_SECRET: "s".repeat(32),
  AUTH_DEV_MODE: false,
  COOKIE_SECURE: "1",
  ALLOW_PRIVATE_WEBHOOKS: false,
  BROKER_DEMO_ALLOW: false,
  CONTROL_PLANE_ENC_KEY: "ab".repeat(32),
  TESSERA_AUTHORITY_HMAC_SECRET: "t".repeat(32),
  SESSION_COOKIE_NAME: "__Host-tessera_session",
  BROKER_ADMIN_KEY: "broker-key",
  BROKER_ADMIN_TOKEN: "broker-admin-token",
};

test("production config accepts a complete secure configuration", () => {
  assert.deepEqual(productionConfigProblems(valid), []);
});

test("production config rejects dev auth, insecure cookies, and demo broker mode", () => {
  const problems = productionConfigProblems({
    ...valid,
    AUTH_DEV_MODE: true,
    COOKIE_SECURE: "0",
    BROKER_DEMO_ALLOW: true,
    ALLOW_PRIVATE_WEBHOOKS: true,
  });
  assert.ok(problems.some((problem) => problem.includes("AUTH_DEV_MODE")));
  assert.ok(problems.some((problem) => problem.includes("COOKIE_SECURE")));
  assert.ok(problems.some((problem) => problem.includes("BROKER_DEMO_ALLOW")));
  assert.ok(problems.some((problem) => problem.includes("ALLOW_PRIVATE_WEBHOOKS")));
});

test("production config rejects missing OIDC, known secrets, and non-HTTPS URLs", () => {
  const problems = productionConfigProblems({
    ...valid,
    PUBLIC_BASE_URL: "http://localhost:5173",
    OIDC_ISSUER: undefined,
    OIDC_STATE_SECRET: undefined,
    CONTROL_PLANE_ENC_KEY: "0x2222222222222222222222222222222222222222222222222222222222222222",
    TESSERA_AUTHORITY_HMAC_SECRET: "tessera-dev-authority-secret-32-bytes-minimum",
    SESSION_COOKIE_NAME: "tessera_session",
  });
  assert.ok(problems.some((problem) => problem.includes("PUBLIC_BASE_URL")));
  assert.ok(problems.some((problem) => problem.includes("OIDC_ISSUER")));
  assert.ok(problems.some((problem) => problem.includes("OIDC_STATE_SECRET")));
  assert.ok(problems.some((problem) => problem.includes("CONTROL_PLANE_ENC_KEY")));
  assert.ok(problems.some((problem) => problem.includes("TESSERA_AUTHORITY_HMAC_SECRET")));
  assert.ok(problems.some((problem) => problem.includes("__Host-")));
});
