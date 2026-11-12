-- OIDC subjects are unique per issuer, not globally.
ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_issuer TEXT;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_oidc_subject_key;
CREATE UNIQUE INDEX IF NOT EXISTS users_oidc_identity_key
    ON users (oidc_issuer, oidc_subject)
    WHERE oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL;
