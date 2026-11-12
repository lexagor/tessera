-- Tessera row-level security (defense in depth).
--
-- Apply with:  psql "$DATABASE_URL" -f infra/sql/rls.sql
--
-- Semantics: a tenant-scoped query runs inside a transaction that sets `app.tenant`
-- (see `apps/broker/src/db.rs`). When the GUC is set, each table is restricted to that
-- tenant even if the query forgets its `tenant = $n` predicate. When the GUC is **unset**
-- (administrative jobs: scheduler sweeps, retention, key bootstrap) the policies evaluate
-- to "allow", so cross-tenant operations keep working.

DO $$
DECLARE
    t text;
    tables text[] := ARRAY[
        'receipt_chain',
        'policies',
        'policy_versions',
        'stripe_grants',
        'telemetry_calls',
        'telemetry_fields',
        'revocations',
        'api_keys',
        'anchors',
        'anchor_targets'
    ];
BEGIN
    FOREACH t IN ARRAY tables LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format($fmt$
            CREATE POLICY tenant_isolation ON %I
                USING (tenant = coalesce(nullif(current_setting('app.tenant', true), ''), tenant))
                WITH CHECK (tenant = coalesce(nullif(current_setting('app.tenant', true), ''), tenant))
        $fmt$, t);
    END LOOP;
END $$;
