-- Tenant lifecycle: retention window, deletion request grace period, and export metadata.
-- Purging is an operator-run workflow documented in docs/data-lifecycle.md; this migration
-- deliberately does not delete tenant or broker data automatically.

ALTER TABLE orgs
    ADD COLUMN IF NOT EXISTS retention_days INTEGER NOT NULL DEFAULT 365
        CHECK (retention_days BETWEEN 30 AND 3650);

ALTER TABLE orgs
    ADD COLUMN IF NOT EXISTS deletion_requested_at TIMESTAMPTZ;

ALTER TABLE orgs
    ADD COLUMN IF NOT EXISTS deletion_scheduled_for TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS orgs_deletion_scheduled_idx
    ON orgs (deletion_scheduled_for)
    WHERE deletion_scheduled_for IS NOT NULL;
