-- SCIM 2.0 provisioning tokens. Tokens are scoped to one organization and stored hashed.
CREATE TABLE IF NOT EXISTS scim_tokens (
    id          UUID PRIMARY KEY,
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS scim_tokens_org_idx ON scim_tokens (org_id, created_at DESC);
