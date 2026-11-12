export const openapi = {
  openapi: "3.1.0",
  info: {
    title: "Tessera Control Plane API",
    version: "0.1.0",
    description:
      "Accounts, environments, agent credentials, actions, evidence, and verification links. Receipt truth remains in the broker.",
  },
  servers: [{ url: "/" }],
  paths: {
    "/healthz": { get: { summary: "Liveness" } },
    "/readyz": { get: { summary: "Readiness (database + broker)" } },
    "/v1/me": { get: { summary: "Current user, org, role, environments" } },
    "/v1/org": { patch: { summary: "Rename the active organization" } },
    "/v1/members": { get: { summary: "Organization members" } },
    "/v1/invites": {
      get: { summary: "Pending invites" },
      post: { summary: "Invite a member" },
    },
    "/v1/environments": {
      get: { summary: "List environments" },
      post: { summary: "Create an environment and broker tenant" },
    },
    "/v1/agent-keys": {
      get: { summary: "List agent keys" },
      post: { summary: "Create an agent API key" },
    },
    "/v1/actions": { get: { summary: "Search actions" } },
    "/v1/actions/{actionId}": { get: { summary: "Action detail and verification" } },
    "/v1/actions/{actionId}/agent-receipt": {
      get: { summary: "Export an Agent Receipts v0.5.0 W3C credential" },
    },
    "/v1/transitions": {
      get: { summary: "Signed authority transition ledger for the environment" },
      post: { summary: "Record a signed authority transition" },
    },
    "/v1/agents": { get: { summary: "Agent summaries for the active environment" } },
    "/v1/usage": { get: { summary: "Usage and plan limits" } },
    "/v1/billing": { get: { summary: "Plan, subscription, and usage" } },
    "/v1/billing/checkout": { post: { summary: "Create a Stripe Checkout session" } },
    "/v1/billing/portal": { post: { summary: "Open the Stripe billing portal" } },
    "/v1/webhooks/stripe": { post: { summary: "Stripe billing webhook" } },
    "/v1/policies": { get: { summary: "List policies" } },
    "/v1/policies/propose": { get: { summary: "Propose a policy from traffic" } },
    "/v1/policies/{id}": {
      get: { summary: "Read a policy" },
      put: { summary: "Upsert a policy version" },
      delete: { summary: "Delete a policy" },
    },
    "/v1/evidence-packs": {
      get: { summary: "List evidence packs" },
      post: { summary: "Build an evidence pack" },
    },
    "/v1/evidence-packs/{id}/download": { get: { summary: "Download an evidence pack" } },
    "/v1/audit": { get: { summary: "Recent control-plane audit events" } },
    "/v1/verification-links": {
      get: { summary: "List verification links" },
      post: { summary: "Create a public verification link" },
    },
    "/v1/verification-links/{id}": {
      delete: { summary: "Revoke a verification link" },
    },
    "/v1/webhooks": {
      get: { summary: "List webhook endpoints" },
      post: { summary: "Create a signed webhook endpoint" },
    },
    "/v1/webhooks/{id}": { delete: { summary: "Delete a webhook endpoint" } },
    "/v1/webhook-deliveries": { get: { summary: "Recent webhook deliveries" } },
    "/v1/webhook-events": { get: { summary: "Supported webhook events" } },
    "/v1/public/verify/{token}": {
      get: { summary: "Public verification payload (no session)" },
    },
    "/v1/authorize": { post: { summary: "Proxy an authorize call to the broker" } },
    "/v1/record": { post: { summary: "Proxy an outcome record to the broker" } },
    "/v1/proxy": { post: { summary: "Proxy a broker-held grant call" } },
  },
} as const;
