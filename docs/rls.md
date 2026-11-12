# Row-Level Security (defense in depth)

Tessera scopes every query by `tenant`, but a future code change could forget a predicate.
Postgres row-level security closes that gap: once enabled, the database itself refuses
cross-tenant rows.

## Runtime role

Production should run the API and broker as `tessera_app`, a `NOSUPERUSER NOBYPASSRLS` role.
The production compose init script creates it on a fresh Postgres volume. Both services refuse
production startup if `DATABASE_URL` resolves to a superuser.

## Enable

After the first broker migration has created the broker tables:

```bash
psql "$DATABASE_URL" -f infra/sql/rls.sql
```

In the production compose stack:

```bash
docker compose -f infra/docker/docker-compose.yml \
  -f infra/docker/docker-compose.prod.yml exec -T postgres \
  psql -U tessera -d tessera -f /sql/rls.sql
```

This applies `ENABLE` + `FORCE ROW LEVEL SECURITY` and a `tenant_isolation` policy to every
tenant table (`receipt_chain`, `policies`, `policy_versions`, `stripe_grants`, `telemetry_*`, `revocations`, `api_keys`,
`anchors`, `anchor_targets`).

## How it works

The policy is:

```sql
USING (tenant = coalesce(nullif(current_setting('app.tenant', true), ''), tenant))
```

- **Tenant-scoped code paths** open their transaction via `db::tenant_tx(pool, tenant)`,
  which runs `set_config('app.tenant', $1, true)` (transaction-local). While set, the policy
  restricts every statement on those tables to that tenant — even a buggy unfiltered
  `SELECT`.
- **Administrative jobs** (scheduler sweeps, retention pruning, API-key bootstrap) do not set
  the GUC, so `current_setting(..., true)` is `NULL`, the `coalesce` falls back to the row's
  own tenant, and the policy allows the full cross-tenant scan.

Because the setting is transaction-local, it cannot leak to another request that reuses
the same pooled connection.

> **Gotchas.**
> - Postgres **superusers bypass RLS** entirely, and table owners bypass it unless
>   `FORCE ROW LEVEL SECURITY` is set (this script sets it). **Run the broker as a
>   non-superuser role** with table grants; otherwise RLS is a no-op.
> - The policy treats both `NULL` and `''` as "administrative access", because a custom GUC
>   can read back as an empty string on a reused connection. Tenant transactions always set a
>   real tenant id, so this fallback is only reachable by admin paths.

## Which code paths set `app.tenant`

| Store | Tenant-scoped methods | Admin methods (no GUC) |
|---|---|---|
| `chain_pg` | `head_hash`, `append`, `find`, `chain`, `len`, `agents_for_tenant` | `tenants`, `prune_idle_agents`, `truncate`, `migrate` |
| `policy_pg` | `list`, `get`, `upsert`, `delete` | `truncate`, `migrate` |
| `anchoring_pg` | `record`, `list`, `latest`, `pending`, `update`, target `set`/`get` | `truncate`, `migrate` |
| `telemetry_pg` | `record`, `stats` | `truncate`, `migrate` |
| `revocation_pg` | `revoke`, `is_revoked`, `list` | `truncate`, `migrate` |
| `auth_pg` | `create`, `list`, `revoke` | `authenticate` (looks up by key hash before the tenant is known) |

`authenticate` deliberately runs without the GUC: it maps a presented key to its tenant, so
the tenant is not yet known. It is keyed by a unique key hash and returns only the tenant id.

## Verify

```bash
TEST_DATABASE_URL=postgres://user@127.0.0.1:5432/tessera_test \
  cargo test --manifest-path apps/broker/Cargo.toml --test rls_postgres
```

The test applies `rls.sql`, writes rows for two tenants, and asserts that an **unfiltered**
`SELECT count(*) FROM receipt_chain` returns only the current tenant's rows while an
administrative query still sees all of them.
