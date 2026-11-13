import { AsyncLocalStorage } from "node:async_hooks";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import postgres, { type Sql } from "postgres";

import { env, isProduction } from "./env.js";

let client: Sql | null = null;
const transactionScope = new AsyncLocalStorage<Sql>();

export const controlPlaneRlsEnabled = env.CONTROL_PLANE_RLS;

function connectRoot(): Sql {
  if (!client) {
    client = postgres(env.DATABASE_URL, {
      max: 10,
      idle_timeout: 20,
      connect_timeout: 10,
      connection: {
        application_name: "tessera-api",
        statement_timeout: 15_000,
        lock_timeout: 5_000,
        idle_in_transaction_session_timeout: 10_000,
      },
      onnotice: () => {},
    });
  }
  return client;
}

export function db(): Sql {
  return transactionScope.getStore() ?? connectRoot();
}

/** Production must not run the control plane as a Postgres superuser. */
export async function assertProductionDatabaseRole(): Promise<void> {
  if (!isProduction) return;
  const rows = await db()`SELECT current_user, current_setting('is_superuser') AS is_superuser`;
  const role = rows[0] as { current_user?: string; is_superuser?: string } | undefined;
  if (role?.is_superuser === "on") {
    throw new Error(
      `DATABASE_URL user '${role.current_user ?? "unknown"}' is a Postgres superuser; use the non-superuser tessera_app role`,
    );
  }
}

/** Run a tenant request inside a transaction with the control-plane RLS GUC set. */
export async function withOrgContext<T>(orgId: string, fn: () => Promise<T>): Promise<T> {
  if (!controlPlaneRlsEnabled || transactionScope.getStore()) return fn();
  return db().begin(async (tx) => {
    await tx`
      SELECT set_config('app.rls', '1', true),
             set_config('app.org_id', ${orgId}, true),
             set_config('app.admin', '0', true)
    `;
    return transactionScope.run(tx as unknown as Sql, fn);
  }) as unknown as Promise<T>;
}

/** Run an explicitly privileged operation (identity bootstrap, cleanup, webhook worker). */
export async function withAdminContext<T>(fn: () => Promise<T>): Promise<T> {
  if (!controlPlaneRlsEnabled || transactionScope.getStore()) return fn();
  return db().begin(async (tx) => {
    await tx`
      SELECT set_config('app.rls', '1', true),
             set_config('app.org_id', '', true),
             set_config('app.admin', '1', true)
    `;
    return transactionScope.run(tx as unknown as Sql, fn);
  }) as unknown as Promise<T>;
}

/** Open a separate privileged transaction even when a request transaction is active. */
export async function withDetachedAdminContext<T>(fn: () => Promise<T>): Promise<T> {
  if (!controlPlaneRlsEnabled) return fn();
  return connectRoot().begin(async (tx) => {
    await tx`
      SELECT set_config('app.rls', '1', true),
             set_config('app.org_id', '', true),
             set_config('app.admin', '1', true)
    `;
    return transactionScope.run(tx as unknown as Sql, fn);
  }) as unknown as Promise<T>;
}

/** Escape hatch for code that must not inherit a request transaction (use deliberately). */
export function detachedDb(): Sql {
  return connectRoot();
}

export async function closeDb(): Promise<void> {
  if (client) {
    await client.end({ timeout: 5 });
    client = null;
  }
}

const HERE = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS = join(HERE, "..", "migrations");

/** Run the idempotent SQL migrations in lexical order. */
export async function migrate(): Promise<void> {
  const connection = await db().reserve();
  try {
    await connection`SELECT pg_advisory_lock(hashtext('tessera_api_migrations'))`;
    await connection`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        name TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `;
    const files = readdirSync(MIGRATIONS)
      .filter((file) => file.endsWith(".sql"))
      .sort();
    for (const file of files) {
      const applied = await connection`
        SELECT 1 FROM schema_migrations WHERE name = ${file}
      `;
      if (applied.length > 0) continue;
      const body = readFileSync(join(MIGRATIONS, file), "utf8");
      await connection.unsafe("BEGIN");
      try {
        await connection.unsafe(body);
        await connection`INSERT INTO schema_migrations (name) VALUES (${file})`;
        await connection.unsafe("COMMIT");
      } catch (error) {
        await connection.unsafe("ROLLBACK").catch(() => {});
        throw error;
      }
    }
  } finally {
    await connection`
      SELECT pg_advisory_unlock(hashtext('tessera_api_migrations'))
    `.catch(() => {});
    connection.release();
  }
}
