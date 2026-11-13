import assert from "node:assert/strict";
import { test } from "node:test";

import { evaluateOidcAccess } from "../src/oidc-access.js";

const base = {
  production: true,
  email: "investor@example.net",
  emailVerified: false,
  allowedDomains: [],
  allowedEmails: ["investor@example.net"],
  unverifiedDemoEmails: [],
  hasInvite: false,
  existingIdentity: false,
  bootstrapAllowed: false,
};

test("production rejects an unverified exact email by default", () => {
  const decision = evaluateOidcAccess(base);
  assert.equal(decision.allowed, false);
  if (!decision.allowed) assert.equal(decision.reason, "email_unverified");
});

test("production accepts an unverified email only in both exact allowlists", () => {
  const decision = evaluateOidcAccess({
    ...base,
    unverifiedDemoEmails: ["investor@example.net"],
  });
  assert.equal(decision.allowed, true);
});

test("unverified demo exception does not extend to domain-only addresses", () => {
  const decision = evaluateOidcAccess({
    ...base,
    email: "someone@thetessera.xyz",
    allowedDomains: ["thetessera.xyz"],
    unverifiedDemoEmails: ["someone@thetessera.xyz"],
  });
  assert.equal(decision.allowed, false);
  if (!decision.allowed) assert.equal(decision.reason, "email_unverified");
});

test("unverified demo exception does not extend to invite-only addresses", () => {
  const decision = evaluateOidcAccess({
    ...base,
    email: "invitee@example.net",
    allowedEmails: [],
    unverifiedDemoEmails: ["invitee@example.net"],
    hasInvite: true,
  });
  assert.equal(decision.allowed, false);
  if (!decision.allowed) assert.equal(decision.reason, "email_unverified");
});
