import * as broker from "./broker.js";
import { db } from "./db.js";
import type { Environment } from "./types.js";

export type NotificationSeverity = "critical" | "warning" | "info";

export interface NotificationItem {
  id: string;
  severity: NotificationSeverity;
  title: string;
  detail: string;
  href: string;
  count: number;
  createdAt: string | null;
}

export async function buildNotifications(
  orgId: string,
  environment: Environment & { broker_key_enc: string | null },
): Promise<NotificationItem[]> {
  const items: NotificationItem[] = [];

  const pendingRows = await db()`
    SELECT count(*)::int AS count, min(r.created_at) AS oldest
      FROM action_reviews r
     WHERE r.org_id = ${orgId}
       AND r.environment_id = ${environment.id}
       AND r.status = 'pending'
  `;
  const pending = (pendingRows[0] ?? {}) as Record<string, any>;
  if (Number(pending.count ?? 0) > 0) {
    items.push({
      id: "reviews-pending",
      severity: "warning",
      title: `${pending.count} action${Number(pending.count) === 1 ? "" : "s"} waiting for review`,
      detail: "A human decision is required before the evidence trail is complete.",
      href: "/reviews",
      count: Number(pending.count),
      createdAt: pending.oldest ? new Date(pending.oldest).toISOString() : null,
    });
  }

  const failedRows = await db()`
    SELECT count(*)::int AS count, max(created_at) AS latest
      FROM actions
     WHERE org_id = ${orgId}
       AND environment_id = ${environment.id}
       AND outcome_status = 'failure'
       AND created_at >= now() - interval '7 days'
  `;
  const failed = (failedRows[0] ?? {}) as Record<string, any>;
  if (Number(failed.count ?? 0) > 0) {
    items.push({
      id: "failed-outcomes",
      severity: "critical",
      title: `${failed.count} failed outcome${Number(failed.count) === 1 ? "" : "s"} in the last 7 days`,
      detail: "Open the attention queue and verify whether the failure was contained.",
      href: "/actions?view=attention",
      count: Number(failed.count),
      createdAt: failed.latest ? new Date(failed.latest).toISOString() : null,
    });
  }

  const unverifiedRows = await db()`
    SELECT count(*)::int AS count, max(created_at) AS latest
      FROM actions
     WHERE org_id = ${orgId}
       AND environment_id = ${environment.id}
       AND outcome_status IS NOT NULL
       AND verified IS NOT TRUE
       AND created_at >= now() - interval '7 days'
  `;
  const unverified = (unverifiedRows[0] ?? {}) as Record<string, any>;
  if (Number(unverified.count ?? 0) > 0) {
    items.push({
      id: "unverified-outcomes",
      severity: "warning",
      title: `${unverified.count} completed action${Number(unverified.count) === 1 ? "" : "s"} not verified`,
      detail: "A completed action is only review-ready after its signature is checked.",
      href: "/actions?view=unverified",
      count: Number(unverified.count),
      createdAt: unverified.latest ? new Date(unverified.latest).toISOString() : null,
    });
  }

  const integrationRows = await db()`
    SELECT provider, name FROM integration_connections
     WHERE org_id = ${orgId}
       AND environment_id = ${environment.id}
       AND status = 'needs_attention'
     ORDER BY updated_at DESC
  `;
  if (integrationRows.length) {
    const names = integrationRows.map((row) => String(row.provider ?? row.name)).slice(0, 4);
    items.push({
      id: "integrations-attention",
      severity: "warning",
      title: `${integrationRows.length} integration${integrationRows.length === 1 ? "" : "s"} need attention`,
      detail: `${names.join(", ")}${integrationRows.length > names.length ? "…" : ""} need a credential or a passing test.`,
      href: "/integrations?filter=attention",
      count: integrationRows.length,
      createdAt: null,
    });
  }

  const packRows = await db()`
    SELECT created_at FROM evidence_packs
     WHERE org_id = ${orgId} AND environment_id = ${environment.id} AND status = 'ready'
     ORDER BY created_at DESC LIMIT 1
  `;
  const latestPack = packRows[0]?.created_at ? new Date(packRows[0].created_at as string) : null;
  if (!latestPack || Date.now() - latestPack.getTime() > 30 * 86_400_000) {
    items.push({
      id: "evidence-freshness",
      severity: latestPack ? "info" : "warning",
      title: latestPack ? "Evidence pack is older than 30 days" : "No evidence pack built yet",
      detail: "Build a reviewer-ready snapshot for the next security review.",
      href: "/evidence",
      count: 1,
      createdAt: latestPack ? latestPack.toISOString() : null,
    });
  }

  const expiringKeyRows = await db()`
    SELECT count(*)::int AS count
      FROM agent_keys
     WHERE environment_id = ${environment.id}
       AND revoked_at IS NULL
       AND expires_at IS NOT NULL
       AND expires_at <= now() + interval '7 days'
  `;
  const expiringKeys = Number((expiringKeyRows[0] as Record<string, unknown> | undefined)?.count ?? 0);
  if (expiringKeys > 0) {
    items.push({
      id: "keys-expiring",
      severity: "warning",
      title: `${expiringKeys} agent key${expiringKeys === 1 ? "" : "s"} expiring soon`,
      detail: "Rotate or extend the key before the agent loses access.",
      href: "/keys",
      count: expiringKeys,
      createdAt: null,
    });
  }

  try {
    const policies = await broker.listPolicies(environment);
    const shadow = Array.isArray(policies.items)
      ? (policies.items as Array<Record<string, any>>).filter(
          (policy) => policy.mode === "monitor" || policy.mode === "recommend",
        )
      : [];
    if (shadow.length) {
      items.push({
        id: "shadow-policies",
        severity: "info",
        title: `${shadow.length} policy${shadow.length === 1 ? "" : "s"} still in shadow mode`,
        detail: `${shadow.map((policy) => String(policy.name ?? policy.id)).slice(0, 3).join(", ")} allow violations with an advisory reason.`,
        href: "/policies",
        count: shadow.length,
        createdAt: null,
      });
    }
  } catch {
    // Notifications must not fail if the broker is temporarily unavailable.
  }

  const rank: Record<NotificationSeverity, number> = { critical: 0, warning: 1, info: 2 };
  return items.sort((a, b) => rank[a.severity] - rank[b.severity]);
}
