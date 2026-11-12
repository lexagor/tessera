-- Cross-replica webhook delivery claims.
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS locked_by TEXT;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS webhook_deliveries_claim_idx
    ON webhook_deliveries (status, next_attempt_at)
    WHERE status = 'pending';
