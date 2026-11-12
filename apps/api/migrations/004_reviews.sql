CREATE TABLE IF NOT EXISTS action_reviews (
    id              UUID PRIMARY KEY,
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    environment_id  UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    action_id       TEXT NOT NULL REFERENCES actions(action_id) ON DELETE CASCADE,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    reason          TEXT,
    requested_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    resolution_note TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ,
    UNIQUE (action_id)
);
CREATE INDEX IF NOT EXISTS action_reviews_org_status_idx
    ON action_reviews (org_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS action_reviews_env_status_idx
    ON action_reviews (environment_id, status, created_at DESC);
