# Integrations and Credential Posture

The Integrations surface shows which systems an agent can reach, who owns each connection, what
permissions it carries, and when Tessera last proved the path. It is a coverage view over the
same action broker and policy engine that authorizes runtime calls.

## Providers

| Provider | Auth mode | Status |
|---|---|---|
| Stripe | Broker-managed restricted keys | GA |
| GitHub | Broker-managed installation tokens | GA |
| AWS | Broker-managed STS sessions | GA |
| Slack | Workspace bot token | Preview |
| Zendesk | API token (basic auth) | Preview |
| OpenAI | API key | Preview |
| Anthropic | API key | Preview |
| LangChain | `@tessera-verify/langchain` SDK | SDK |

Preview providers can be configured and governed today. Their production issuer adapter is not
wired into the broker yet; local demo mode registers mock issuers so the end-to-end setup test
action still runs without a live provider credential.

## Connecting a provider

A connection does three things:

1. creates a least-privilege baseline policy from the selected scopes;
2. issues a real policy test action through the action broker and records the receipt; and
3. stores the connection's credential posture, owner, environment, and scope.

Credentials are encrypted with `CONTROL_PLANE_ENC_KEY` (AES-256-GCM) and are never returned by
the API. Broker-managed providers do not require a pasted secret; optional credentials can be
added to run a live connection test.

## Test and rotate

- **Test connection** exercises the stored credential against the provider (or validates the
  broker-managed path), updates `last sync`, and reports the provider account where available.
- **Rotate credential** replaces the encrypted credential and moves the connection to
  `needs_attention` until the next successful test.

Network probes use fixed provider endpoints and an 8-second timeout. The Zendesk subdomain is
validated before use. The live probe is disabled in tests; the suite validates configuration and
policy/test-action creation instead.

## API

| Endpoint | Purpose |
|---|---|
| `GET /v1/integrations` | Provider catalog, connections, status, scopes, owner, last sync |
| `POST /v1/integrations` | Connect a provider, create the first policy, and run a test action |
| `POST /v1/integrations/:id/test` | Test the provider connection and update credential posture |
| `POST /v1/integrations/:id/rotate` | Replace the encrypted credential |

## What this proves

The page makes governed surface area visible: which providers are connected, which need
attention, which scopes are allowed, and who owns each connection. It does not claim a live
issuer adapter for every preview provider. The authoritative record for each setup test is the
signed action in the broker, linkable from the provider card.
