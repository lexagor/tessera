-- Evidence pack review reports and share links.
--
-- summary is a point-in-time snapshot of the evidence posture at pack creation.
-- share_token_hash enables a bearer "reviewer link" for an auditor; the token itself
-- is never stored.

ALTER TABLE evidence_packs
    ADD COLUMN IF NOT EXISTS summary JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE evidence_packs
    ADD COLUMN IF NOT EXISTS share_token_hash TEXT;

ALTER TABLE evidence_packs
    ADD COLUMN IF NOT EXISTS share_expires_at TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS evidence_packs_share_token_idx
    ON evidence_packs (share_token_hash)
    WHERE share_token_hash IS NOT NULL;
