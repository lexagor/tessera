-- SCIM 2.0 Groups, mapped to workspace roles. Group membership is additive to workspace
-- membership; removing a group does not remove the underlying membership.
CREATE TABLE IF NOT EXISTS scim_groups (
    id            UUID PRIMARY KEY,
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    display_name  TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'member', 'viewer')),
    members       JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, display_name)
);
CREATE INDEX IF NOT EXISTS scim_groups_org_idx ON scim_groups (org_id, created_at DESC);

ALTER TABLE scim_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_groups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON scim_groups;
CREATE POLICY tenant_isolation ON scim_groups
    USING (
        coalesce(current_setting('app.rls', true), '') <> '1'
        OR coalesce(current_setting('app.admin', true), '') = '1'
        OR org_id = nullif(current_setting('app.org_id', true), '')::uuid
    )
    WITH CHECK (
        coalesce(current_setting('app.rls', true), '') <> '1'
        OR coalesce(current_setting('app.admin', true), '') = '1'
        OR org_id = nullif(current_setting('app.org_id', true), '')::uuid
    );
