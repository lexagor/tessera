ALTER TABLE scim_tokens ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS scim_tokens_expiry_idx
    ON scim_tokens (expires_at)
    WHERE expires_at IS NOT NULL AND revoked_at IS NULL;
