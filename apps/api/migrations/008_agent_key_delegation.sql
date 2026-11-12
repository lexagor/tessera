-- Bind agent keys to the human who created them.
--
-- delegation_mode:
--   caller — the agent supplies userId/principal; no cryptographic authority binding.
--   owner  — the API mints a short-lived authority token for the key owner on every authorize.
--   token  — the agent supplies a per-call authority token minted by POST /v1/authority-tokens.

ALTER TABLE agent_keys
    ADD COLUMN IF NOT EXISTS delegated_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS delegation_mode TEXT NOT NULL DEFAULT 'caller';

ALTER TABLE agent_keys
    DROP CONSTRAINT IF EXISTS agent_keys_delegation_mode_check;

ALTER TABLE agent_keys
    ADD CONSTRAINT agent_keys_delegation_mode_check
    CHECK (delegation_mode IN ('caller', 'owner', 'token'));

CREATE INDEX IF NOT EXISTS agent_keys_delegated_user_idx
    ON agent_keys (delegated_user_id)
    WHERE delegated_user_id IS NOT NULL;
