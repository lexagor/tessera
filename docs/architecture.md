# Architecture

Tessera is the proof layer for agent actions. The Rust broker is the enforcement and
evidence engine; the TypeScript control plane owns accounts, environments, agent credentials,
the action read model, and customer-facing verification.

## Components

```
agent / SDK / MCP
        │  agent API key
        ▼
apps/api  ── public control plane + BFF ──▶ apps/broker (private hot path)
  accounts / OIDC sessions / RBAC              authorize / record / proxy
  environments / agent keys                    policy / receipts / chain / verify
  actions / usage / evidence                   issuers / durable grants
  verification links / audit
        ▲
apps/portal   tenant UI
apps/verify   public verification links + bundle verifier
apps/site     marketing, docs, pricing, trust center
```

| Path | Language | Role |
|---|---|---|
| `apps/broker` | Rust | Enforcement, credential issuance, signed records, chains, verification |
| `apps/api` | TypeScript | Public control plane: OIDC, tenancy, environments, agent keys, action read model, usage, evidence, verification links |
| `apps/portal` | TypeScript | Tenant portal (Overview, Actions, Agents, Evidence, Transitions, Policies, Keys, Team, Settings) |
| `apps/verify` | TypeScript | Public verifier: links, uploaded records, offline checks |
| `apps/site` | TypeScript | Static landing page and public docs |
| `packages/sdk-ts` | TypeScript | Agent SDK |
| `packages/sdk-py` | Python | Agent SDK |
| `packages/receipt-schema` | TypeScript | Receipt v2 schema, hashing, EIP-712 types |
| `packages/verifier` | TypeScript | Independent v1/v2 verifier |
| `packages/mcp-adapter` | TypeScript | MCP tool-call middleware |
| `packages/langchain` | TypeScript | LangChain tool wrapper |
| `packages/agent-receipts` | TypeScript | Agent Receipts v0.5.0 / W3C VC export |
| `packages/ui` | TypeScript | Shared portal/verifier design tokens and primitives |
| `contracts/receipts` | Solidity | Optional Merkle anchor |
| `infra/docker` | YAML | VPS compose stack |

## Request flow

1. An agent calls the control plane with an agent API key:
   `POST /v1/authorize`.
2. The API resolves the key to an environment, checks it is active, and proxies the call to
   the broker with that environment's broker key.
3. The broker evaluates policy (CEL + deterministic constraints), issues a scoped credential
   or broker-held grant, signs a v2 authorization record, and appends it to the agent chain.
4. The API writes an action read-model row (authorization + hashes + summary), upserts the
   agent, and increments usage.
5. The agent executes the tool call. For broker-held grants the broker observes the upstream
   response and appends the linked outcome itself (`outcome.source = broker_observed`). For
   direct credentials the agent calls `POST /v1/record` (`agent_reported`). The API updates the
   action row either way.
6. The portal and public verifier read the action read model and call the broker/verifier to
   check signatures and chains.

## Authentication

- **Humans:** invite-only OIDC (generic issuer; Google/GitHub first) with HttpOnly sessions,
  CSRF/origin checks on writes, and RBAC (`owner`, `admin`, `member`, `viewer`).
- **Agents:** per-environment API keys issued by the control plane (`tsk_live_…`), stored as
  SHA-256 hashes with a display prefix; raw keys are shown once.
- **Broker:** internal only. The control plane holds one broker key per environment,
  encrypted with `CONTROL_PLANE_ENC_KEY`; the broker is not exposed publicly.
- **Authority tokens:** the control plane mints short-lived HS256 JWTs for authenticated OIDC
  sessions (`TESSERA_AUTHORITY_HMAC_SECRET`). Agent keys can be owner-bound (the API mints per
  request) or token-delegated (the agent supplies a per-call token from
  `POST /v1/authority-tokens`). Tokens carry `iss`, `aud`, `tenant`, `agent_id`, and `jti`;
  the broker validates them, rejects replay within the token TTL, and records
  `verificationMethod: "hmac-jwt"`, binding the delegating principal to v2 records. Key
  rotation uses a `kid` keyring with an optional previous secret. The explicit mint endpoint
  is per-user rate-limited; owner-bound keys mint per authorize call.

## Webhooks

Tenants can subscribe to signed control-plane events (`action.created`, `action.completed`,
`action.denied`, evidence, verification links, keys, environments, and policy changes).
Deliveries are persisted, retried with backoff, and signed with HMAC-SHA256 over
`timestamp.body`. See [`webhooks.md`](webhooks.md).

## Control-plane data

Postgres tables: `orgs`, `users`, `memberships`, `invites`, `sessions`, `environments`,
`agents`, `agent_keys` (including `delegation_mode` and `delegated_user_id`), `actions`,
`usage_daily`, `verification_links`, `evidence_packs`, `audit_log`, and billing tables added
with the billing phase.

The control plane is a read model over broker evidence, not a replacement for it. Receipts and
chains remain authoritative in the broker; `actions` is rebuildable from broker chains.

## Broker storage

- **Postgres** — policies + immutable `policy_versions`, receipt chain
  (`receipt_chain`, hash-partitioned by agent), Stripe grants (`stripe_grants`,
  envelope-encrypted), API keys, revocations, anchors, telemetry, key events, checkpoints.
- **Redis** — API-key cache and shared rate limiting (`REDIS_URL`).
- **In-memory** — dev/test fallback for stores when `DATABASE_URL` is unset.
- **Evidence archive** — signed tenant archive with receipts, policies, key events,
  checkpoints, anchors, and control mapping.
- **Authority transitions** — revocations, rotations, and scope changes are appended to the
  signed key-event ledger as `authority.*` events and surfaced in the portal.

## Receipts and verification

- Receipt v2 binds the agent, delegating principal, intent, policy hash/version, tool
  definition, arguments, credential thumbprint, and outcome.
- Authorization and outcome are separate linked records sharing `actionId`; the outcome
  carries `authorizationReceiptId` and links to the current chain head. Old immediate
  outcomes remain verifiable via `prev`.
- Proxy outcomes are broker-observed; the envelope also exports to Agent Receipts v0.5.0 /
  W3C VC with an Ed25519 proof and optional RFC 3161 timestamp.
- EIP-712 signatures; v2 uses domain version `"2"`. High-S signatures are rejected.
- Verification supports v1/v2 receipts, action pairs, chains, and Merkle proofs without the
  broker key. `/v1/public/verify/:token` resolves revocable verification links.

## Policy and grants

- Policies are CEL + deterministic constraints, deny-by-default.
- Policy versions are immutable: changing content requires a version bump.
- Stripe grants are single-use, tenant-scoped, argument-bound, and durable across restarts
  and replicas when Postgres is configured.

## Deployment

- **Pilots:** Docker Compose on one VPS behind Caddy: `api`, `portal`, `verify`, `broker`,
  Postgres, Redis, and optional MinIO/S3 for evidence.
- **Later:** Helm with managed Postgres/Redis and object storage; broker private behind the
  control plane.
- **Anchoring:** optional; RFC 3161/transparency-log timestamping is the enterprise default.

## Design principles

1. Fail closed on the enforcement path.
2. The broker holds provider secrets; agents receive only scoped material.
3. Every consequential action produces a signed record.
4. The public contract is action-centric and stable; receipt schemas version separately.
5. Evidence must be portable and independently verifiable.
