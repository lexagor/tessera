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
The portal Settings page shows recent deliveries and their status/last error.

## Security

- Production endpoints must use HTTPS.
- Private/localhost literal hosts are rejected unless `ALLOW_PRIVATE_WEBHOOKS=1` is set for
  local development. DNS-based egress controls are the next hardening step for production.
- Keep the signing secret out of logs and client-side code.
