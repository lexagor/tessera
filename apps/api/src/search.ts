import * as broker from "./broker.js";
import { db } from "./db.js";
import type { Environment } from "./types.js";

export interface SearchResult {
  actions: Array<{
    actionId: string;
    tool: string;
    agentId: string;
    decision: string;
    createdAt: string;
  }>;
  agents: Array<{ agentId: string; actions: number; lastSeen: string }>;
  policies: Array<{ id: string; name: string; version: number; mode?: string }>;
  verificationLinks: Array<{
    id: string;
    actionId: string;
    tool: string;
    createdAt: string;
  }>;
}

export async function searchResources(
  orgId: string,
  environment: Environment & { broker_key_enc: string | null },
  query: string,
): Promise<SearchResult> {
  const q = query.trim().slice(0, 100);
  if (!q) return { actions: [], agents: [], policies: [], verificationLinks: [] };
  const pattern = `%${q}%`;

  const actionRows = await db()`
    SELECT action_id, tool, agent_id, decision, created_at
      FROM actions
     WHERE org_id = ${orgId}
       AND environment_id = ${environment.id}
       AND (tool ILIKE ${pattern} OR agent_id ILIKE ${pattern} OR action_id ILIKE ${pattern})
     ORDER BY created_at DESC LIMIT 8
  `;
  const agentRows = await db()`
    SELECT agent_id, count(*)::int AS actions, max(created_at) AS last_seen
      FROM actions
     WHERE org_id = ${orgId}
       AND environment_id = ${environment.id}
       AND agent_id ILIKE ${pattern}
     GROUP BY agent_id ORDER BY last_seen DESC LIMIT 5
  `;
  const linkRows = await db()`
    SELECT vl.id, vl.action_id, a.tool, vl.created_at
      FROM verification_links vl
      JOIN actions a ON a.action_id = vl.action_id
     WHERE vl.org_id = ${orgId}
       AND vl.environment_id = ${environment.id}
       AND vl.revoked_at IS NULL
       AND (vl.action_id ILIKE ${pattern} OR a.tool ILIKE ${pattern})
     ORDER BY vl.created_at DESC LIMIT 5
  `;

  let policyItems: Array<{ id: string; name: string; version: number; mode?: string }> = [];
  try {
    const response = await broker.listPolicies(environment);
    policyItems = Array.isArray(response.items)
      ? (response.items as Array<Record<string, any>>)
          .filter((policy) => {
            const haystack = `${policy.id ?? ""} ${policy.name ?? ""}`.toLowerCase();
            return haystack.includes(q.toLowerCase());
          })
          .slice(0, 5)
          .map((policy) => ({
            id: String(policy.id),
            name: String(policy.name ?? policy.id),
            version: Number(policy.version ?? 0),
            mode: typeof policy.mode === "string" ? policy.mode : "enforce",
          }))
      : [];
  } catch {
    policyItems = [];
  }

  return {
    actions: (actionRows as Array<Record<string, any>>).map((row) => ({
      actionId: String(row.action_id),
      tool: String(row.tool),
      agentId: String(row.agent_id),
      decision: String(row.decision),
      createdAt: new Date(row.created_at).toISOString(),
    })),
    agents: (agentRows as Array<Record<string, any>>).map((row) => ({
      agentId: String(row.agent_id),
      actions: Number(row.actions),
      lastSeen: new Date(row.last_seen).toISOString(),
    })),
    policies: policyItems,
    verificationLinks: (linkRows as Array<Record<string, any>>).map((row) => ({
      id: String(row.id),
      actionId: String(row.action_id),
      tool: String(row.tool),
      createdAt: new Date(row.created_at).toISOString(),
    })),
  };
}
