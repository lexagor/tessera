-- Integration coverage and credential posture.
--
-- A connection records the governance scope for a provider in one environment. Provider
-- credentials are optional for broker-managed providers and are always encrypted at rest.

CREATE TABLE IF NOT EXISTS integration_connections (
    id                    UUID PRIMARY KEY,
    org_id                UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    environment_id        UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    provider              TEXT NOT NULL,
    name                  TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'needs_attention'
                          CHECK (status IN ('connected', 'needs_attention', 'disabled')),
    auth_mode             TEXT NOT NULL
                          CHECK (auth_mode IN ('broker_managed', 'api_key', 'basic', 'sdk')),
    scopes                JSONB NOT NULL DEFAULT '[]'::jsonb,
    owner_user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    credential_ciphertext TEXT,
    credential_hint       TEXT,
    metadata              JSONB NOT NULL DEFAULT '{}'::jsonb,
    policy_id             TEXT,
    test_action_id        TEXT,
    last_sync_at          TIMESTAMPTZ,
    last_tested_at        TIMESTAMPTZ,
    last_test_ok          BOOLEAN,
    last_test_message     TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (environment_id, provider)
);

CREATE INDEX IF NOT EXISTS integration_connections_org_idx
    ON integration_connections (org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS integration_connections_env_idx
    ON integration_connections (environment_id, provider);
