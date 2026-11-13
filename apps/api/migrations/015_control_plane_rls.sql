-- Control-plane row-level security, feature-flagged at runtime by `app.rls`.
--
-- Policies allow everything while `CONTROL_PLANE_RLS` is off, so this migration is safe to
-- apply before the API is ready to set the transaction-local GUC. When the feature is enabled,
-- the API sets app.rls=1 plus either app.org_id or app.admin=1 for every transaction. Admin
-- jobs and identity bootstrap use app.admin; all tenant requests use app.org_id.
--
-- `users` is a global identity table and is intentionally excluded; membership and tenant data
-- are protected by the policies below.

DO $$
DECLARE
    t text;
    tables text[] := ARRAY[
        'actions',
        'action_reviews',
        'audit_log',
        'billing_subscriptions',
        'environments',
        'evidence_packs',
        'integration_connections',
        'invites',
        'memberships',
        'scim_tokens',
        'sessions',
        'usage_daily',
        'verification_links',
        'webhook_deliveries',
        'webhook_endpoints'
    ];
BEGIN
    FOREACH t IN ARRAY tables LOOP
        IF to_regclass(format('public.%I', t)) IS NULL THEN
            RAISE NOTICE 'skipping missing control-plane table %', t;
            CONTINUE;
        END IF;
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format($fmt$
            CREATE POLICY tenant_isolation ON %I
                USING (
                    coalesce(current_setting('app.rls', true), '') <> '1'
                    OR coalesce(current_setting('app.admin', true), '') = '1'
                    OR org_id = nullif(current_setting('app.org_id', true), '')::uuid
                )
                WITH CHECK (
                    coalesce(current_setting('app.rls', true), '') <> '1'
                    OR coalesce(current_setting('app.admin', true), '') = '1'
                    OR org_id = nullif(current_setting('app.org_id', true), '')::uuid
                )
        $fmt$, t);
    END LOOP;

    -- The organization row is keyed by id rather than org_id.
    ALTER TABLE orgs ENABLE ROW LEVEL SECURITY;
    ALTER TABLE orgs FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation ON orgs;
    CREATE POLICY tenant_isolation ON orgs
        USING (
            coalesce(current_setting('app.rls', true), '') <> '1'
            OR coalesce(current_setting('app.admin', true), '') = '1'
            OR id = nullif(current_setting('app.org_id', true), '')::uuid
        )
        WITH CHECK (
            coalesce(current_setting('app.rls', true), '') <> '1'
            OR coalesce(current_setting('app.admin', true), '') = '1'
            OR id = nullif(current_setting('app.org_id', true), '')::uuid
        );

    -- Environment children inherit the organization boundary through a subquery.
    FOREACH t IN ARRAY ARRAY['agents', 'agent_keys'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format($fmt$
            CREATE POLICY tenant_isolation ON %I
                USING (
                    coalesce(current_setting('app.rls', true), '') <> '1'
                    OR coalesce(current_setting('app.admin', true), '') = '1'
                    OR environment_id IN (
                        SELECT id FROM environments
                         WHERE org_id = nullif(current_setting('app.org_id', true), '')::uuid
                    )
                )
                WITH CHECK (
                    coalesce(current_setting('app.rls', true), '') <> '1'
                    OR coalesce(current_setting('app.admin', true), '') = '1'
                    OR environment_id IN (
                        SELECT id FROM environments
                         WHERE org_id = nullif(current_setting('app.org_id', true), '')::uuid
                    )
                )
        $fmt$, t);
    END LOOP;
END $$;
