-- Time-to-verification analytics. The first successful independent check records this once;
-- subsequent reads do not move the timestamp.

ALTER TABLE actions
    ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS actions_verified_at_idx
    ON actions (org_id, environment_id, verified_at)
    WHERE verified_at IS NOT NULL;
