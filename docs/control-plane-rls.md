# Control-Plane RLS Design

**Status:** implemented behind `CONTROL_PLANE_RLS`; the live flag remains off until a canary rollout. Policies are safe to apply with the flag off.

Broker tables use Postgres row-level security today. Control-plane tables (`orgs`,
`memberships`, `environments`, `actions`, `agent_keys`, `evidence_packs`, `webhooks`, `audit_log`)
still rely on application predicates. This document defines the safe path to defense in depth.

## Goal

A missed `org_id` predicate must not return another tenant's row. The database, not only the
Hono route, enforces the boundary. Administrative jobs and migrations retain a deliberate
bypass.

## Proposed policy

Use a transaction-local GUC set by a control-plane transaction helper:

```sql
SELECT set_config('app.org_id', $1, true);
```

For every table with a direct `org_id` column:

```sql
ALTER TABLE actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE actions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON actions
  USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);
```

For `orgs`, use `id`; for `memberships`, `org_id`; for `environments`, `environment_id` join to
`org_id`; for `sessions`, `org_id`; for `users`, policies must support multi-workspace identity
and are out of scope for the first pass. `schema_migrations` and broker administrative tables
are not control-plane tenant tables.

Unlike the broker policy, the control-plane policy should **deny** when the GUC is unset. Admin
jobs must opt in through a dedicated `adminTx()` that sets an explicit `app.admin = 1` policy
branch or uses a separate migration role. A silent allow-on-unset rule is too easy to abuse in
the request path.

## Runtime shape

- Add `db.orgTx(orgId, fn)` that begins a transaction, sets `app.org_id`, runs queries, and
  commits/rolls back.
- Route middleware resolves the session and wraps every `/v1/*` request after auth. Auth lookups
  before the org is known use a narrow `admin` or `identity` transaction.
- Background jobs (webhook delivery, session cleanup, deletion scheduler) use `adminTx()` with
  an explicit audit reason.
- The pool remains `tessera_app` (`NOSUPERUSER NOBYPASSRLS`); `FORCE RLS` applies even to the
  table owner.
- Never use `SET` (session-scoped) for the GUC; use `SET LOCAL`/`set_config(..., true)` so a
  pooled connection cannot leak a tenant.

## Rollout

1. Add the transaction helpers and a `CONTROL_PLANE_RLS` feature flag.
2. Add a shadow mode that runs the policy check in a read-only transaction and logs would-be
   denials. No enforcement yet.
3. Add integration tests for every table: tenant A cannot read/write B with the GUC set; admin
   bypass requires an explicit flag; unset GUC denies.
4. Apply policies to a staging database with a production-shaped dataset.
5. Enable `ENABLE ROW LEVEL SECURITY` without `FORCE`, canary one read-only request path.
6. Enable `FORCE`, run the full test suite and a rollback drill.
7. Update the threat model, RLS docs, and claim boundaries.

## Risks and open questions

- `users` are global identities and may belong to several orgs; policies need a membership
  subquery or a separate identity table.
- Some routes join across tenants for admin/operator views; those must use `adminTx()` and be
  audited.
- Prisma/postgres.js transaction discipline must be consistent; a missed wrapper is a bypass.
- A migration role must not be the runtime role; the prod startup check already refuses a
  superuser.
- Deletion and export jobs need careful scoping so a purge cannot cross tenants.

Until all of this is implemented and tested, the accurate claim is: **broker RLS is enforced;
control-plane isolation is application-enforced and tested, not database-enforced.**

## Enablement (implemented, default off)

The migration `015_control_plane_rls.sql` is safe to apply while the feature is off: policies
allow access when `app.rls` is unset. To enable enforcement:

```bash
# 1. Test locally with the API/DB tests.
TEST_DATABASE_URL=... CONTROL_PLANE_RLS=1 pnpm --filter @tessera/api test

# 2. Set the flag on one staging instance and run the full smoke suite.
CONTROL_PLANE_RLS=1

# 3. Canary production after verifying auth/login, SCIM, webhook delivery, cleanup jobs,
#    billing webhook, and background workers. Roll back by setting CONTROL_PLANE_RLS=0.
```

When enabled, `withOrgContext()` sets `app.rls=1` and `app.org_id`; `withAdminContext()` sets
`app.rls=1`, `app.org_id=''`, and `app.admin=1`. Auth bootstrap, session lookup, SCIM token
lookup, webhook enqueue/worker, and cleanup jobs use the admin path. The live flag remains off
until a production canary is approved.

## Verification

```bash
DATABASE_URL=... RLS_REQUIRE_TABLES=1 infra/scripts/check-control-plane-rls.sh
```

The CI node job runs this after migrations. The API also runs `assertControlPlaneRlsPolicies()`
at production startup and refuses to boot if any expected table lacks `ENABLE` + `FORCE` or a
policy. Policy existence is not a substitute for the transaction-helper tests.
