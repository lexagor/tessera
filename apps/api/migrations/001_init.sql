-- Tessera control-plane schema.
--
-- Tenant truth stays in the broker (receipts/chains). These tables hold accounts,
-- environments, agent credentials, the action read model, and customer-facing evidence.

CREATE TABLE IF NOT EXISTS orgs (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    plan        TEXT NOT NULL DEFAULT 'team',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    name          TEXT,
    oidc_subject  TEXT UNIQUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS memberships (
    org_id     UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE IF NOT EXISTS invites (
    id          UUID PRIMARY KEY,
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('admin', 'member', 'viewer')),
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS invites_email_idx ON invites (lower(email));

CREATE TABLE IF NOT EXISTS sessions (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id       UUID REFERENCES orgs(id) ON DELETE SET NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id);

CREATE TABLE IF NOT EXISTS environments (
    id             UUID PRIMARY KEY,
    org_id         UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    slug           TEXT NOT NULL,
    broker_tenant  TEXT NOT NULL UNIQUE,
    broker_key_enc TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, slug)
);

CREATE TABLE IF NOT EXISTS agents (
    id             UUID PRIMARY KEY,
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    agent_id       TEXT NOT NULL,
    name           TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (environment_id, agent_id)
);

CREATE TABLE IF NOT EXISTS agent_keys (
    id             UUID PRIMARY KEY,
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    prefix         TEXT NOT NULL,
    key_hash       TEXT NOT NULL UNIQUE,
    scopes         JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at     TIMESTAMPTZ,
    revoked_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS agent_keys_env_idx ON agent_keys (environment_id);

CREATE TABLE IF NOT EXISTS actions (
    action_id              TEXT PRIMARY KEY,
    org_id                 UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    environment_id         UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    agent_id               TEXT NOT NULL,
    principal_id           TEXT,
    tool                   TEXT NOT NULL,
    decision               TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
    outcome_status         TEXT,
    policy_id              TEXT,
    policy_version         INTEGER,
    policy_hash            TEXT,
    credential_issuer      TEXT,
    credential_thumbprint  TEXT,
    receipt_id             TEXT NOT NULL,
    outcome_receipt_id     TEXT,
    created_at             TIMESTAMPTZ NOT NULL,
    completed_at           TIMESTAMPTZ,
    verified               BOOLEAN,
    payload                JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS actions_org_time_idx ON actions (org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS actions_env_time_idx ON actions (environment_id, created_at DESC);
CREATE INDEX IF NOT EXISTS actions_agent_time_idx ON actions (environment_id, agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS actions_decision_idx ON actions (org_id, decision);
CREATE INDEX IF NOT EXISTS actions_outcome_idx ON actions (org_id, outcome_status);
CREATE INDEX IF NOT EXISTS actions_receipt_idx ON actions (receipt_id);

CREATE TABLE IF NOT EXISTS usage_daily (
    org_id         UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    day            DATE NOT NULL,
    actions        INTEGER NOT NULL DEFAULT 0,
    allowed        INTEGER NOT NULL DEFAULT 0,
    denied         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (org_id, environment_id, day)
);

CREATE TABLE IF NOT EXISTS verification_links (
    id             UUID PRIMARY KEY,
    org_id         UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    action_id      TEXT NOT NULL REFERENCES actions(action_id) ON DELETE CASCADE,
    token_hash     TEXT NOT NULL UNIQUE,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    view_count     INTEGER NOT NULL DEFAULT 0,
    revoked_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS verification_links_action_idx ON verification_links (action_id);

CREATE TABLE IF NOT EXISTS evidence_packs (
    id             UUID PRIMARY KEY,
    org_id         UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    status         TEXT NOT NULL,
    object_key     TEXT,
    filters        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS evidence_packs_org_idx ON evidence_packs (org_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_log (
    id             UUID PRIMARY KEY,
    org_id         UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    actor_user_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_type     TEXT NOT NULL,
    action         TEXT NOT NULL,
    target         TEXT,
    details        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_org_time_idx ON audit_log (org_id, created_at DESC);
