# Webhooks

The control plane delivers signed webhook events to tenant endpoints. Configure endpoints in
the portal Settings page or via `POST /v1/webhooks`.

## Events

- `action.created`
- `action.completed`
- `action.denied`
- `verification_link.created`
- `evidence_pack.created`
- `agent_key.created`
- `agent_key.revoked`
- `environment.created`
- `policy.upserted`

An endpoint with `events: ["*"]` receives every event.

## Payload

```json
{
  "event": "action.created",
  "createdAt": "2026-11-11T16:21:37.770Z",
  "data": {
    "actionId": "…",
    "environmentId": "…",
    "agentId": "billing-agent",
    "principalId": "user_42",
    "tool": "stripe.refunds.create",
    "decision": "allow",
    "receiptId": "0x…"
  }
}
```

## Signature

Each delivery includes:

- `x-tessera-event`
- `x-tessera-timestamp` (Unix seconds)
- `x-tessera-signature: sha256=<hex>`

Verify with the endpoint secret returned once at creation:

```text
sha256=HMAC_SHA256(secret, `${timestamp}.${rawBody}`)
```

Reject deliveries older than a short window (for example, five minutes) and compare the
signature in constant time. The secret is stored encrypted at rest and is never returned again.

## Retries

Deliveries are durable. Failed attempts retry with exponential backoff up to five attempts.
Workers claim due rows with `FOR UPDATE SKIP LOCKED` and a two-minute lease, so multiple API
replicas do not normally deliver the same row at once. Delivery remains at-least-once; use the
event and payload fields to make your handler idempotent. The portal Settings page shows recent
deliveries and their status/last error.

## Security

- Production endpoints must use HTTPS.
- Delivery resolves the destination and rejects private, loopback, link-local, metadata,
  documentation, and reserved addresses. The resolved address is pinned for the request to
  reduce DNS-rebinding risk.
- Redirects are rejected; webhook handlers must respond directly.
- Private/localhost targets are rejected unless `ALLOW_PRIVATE_WEBHOOKS=1` is set for local
  development. Never enable that in production.
- Response bodies are drained with a 64 KiB cap; only the status code decides success.
- Keep the signing secret out of logs and client-side code.
