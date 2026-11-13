import assert from "node:assert/strict";
import { test } from "node:test";

process.env.NODE_ENV = "test";
process.env.DATABASE_URL = process.env.DATABASE_URL ?? "postgres://unused";

const { emailConfigured, inviteEmail, deletionRequestEmail } = await import("../src/email.js");

test("email is disabled without a provider and key", () => {
  assert.equal(emailConfigured(), false);
});

test("invite email includes the invite URL and inviter", () => {
  const message = inviteEmail({
    to: "reviewer@example.com",
    inviteUrl: "https://app.example/invite/token",
    orgName: "Acme <Security>",
    inviterEmail: "owner@example.com",
    role: "viewer",
  });
  assert.equal(message.to, "reviewer@example.com");
  assert.match(message.subject, /Acme/);
  assert.match(message.text, /https:\/\/app\.example\/invite\/token/);
  assert.match(message.html ?? "", /Acme &lt;Security&gt;/);
});

test("deletion email names the purge date", () => {
  const message = deletionRequestEmail({
    to: "owner@example.com",
    orgName: "Acme",
    purgeAfter: "2026-12-13T00:00:00.000Z",
  });
  assert.match(message.text, /2026-12-13T00:00:00.000Z/);
});
