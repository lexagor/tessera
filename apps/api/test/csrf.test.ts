import assert from "node:assert/strict";
import { test } from "node:test";

process.env.NODE_ENV = "test";
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? "postgres://unused";
process.env.PUBLIC_BASE_URL = "https://app.thetessera.xyz";

const { trustedWriteOrigin } = await import("../src/csrf.js");

test("trusted writes require an allowed Origin in strict mode", () => {
  const allowed = ["https://app.thetessera.xyz"];
  assert.equal(
    trustedWriteOrigin("https://app.thetessera.xyz", { strict: true, allowedOrigins: allowed }),
    true,
  );
  assert.equal(
    trustedWriteOrigin("https://evil.example", { strict: true, allowedOrigins: allowed }),
    false,
  );
  assert.equal(trustedWriteOrigin(undefined, { strict: true, allowedOrigins: allowed }), false);
  assert.equal(trustedWriteOrigin("null", { strict: true, allowedOrigins: allowed }), false);
});

test("non-strict mode allows non-browser clients without Origin", () => {
  assert.equal(trustedWriteOrigin(undefined, { strict: false }), true);
  assert.equal(
    trustedWriteOrigin("https://evil.example", {
      strict: false,
      allowedOrigins: ["https://app.thetessera.xyz"],
    }),
    false,
  );
});
