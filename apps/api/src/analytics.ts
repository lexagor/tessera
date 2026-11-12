import { db } from "./db.js";
import type { Environment } from "./types.js";
import { dayKeys, normalizeTimeWindow, type TimeWindow } from "./time.js";

export interface AnalyticsDay {
  day: string;
  actions: number;
  allowed: number;
  denied: number;
  failed: number;
  verified: number;
  brokerObserved: number;
  agentReported: number;
}

export interface AnalyticsTool {
  tool: string;
  actions: number;
  allowed: number;
  denied: number;
  failed: number;
  verified: number;
}

export interface AnalyticsPolicy {
  policyId: string;
  actions: number;
  denied: number;
  verified: number;
}

export interface AnalyticsResult {
  window: TimeWindow;
  totals: {
    actions: number;
    allowed: number;
    denied: number;
    completed: number;
    failed: number;
    verified: number;
    brokerObserved: number;
    agentReported: number;
    agents: number;
    governed: number;
    ungoverned: number;
    policies: number;
    reviews: number;
    pendingReviews: number;
    verificationLinks: number;
    evidencePacks: number;
  };
  rates: {
    allow: number;
    deny: number;
    verifiedOutcome: number;
    policyCoverage: number;
  };
  series: AnalyticsDay[];
  tools: AnalyticsTool[];
  policies: AnalyticsPolicy[];
  heatmap: {
    agents: Array<{ agentId: string; actions: number; denied: number }>;
    days: string[];
    cells: Array<{ agentId: string; day: string; actions: number; denied: number }>;
  };
  verification: {
    sample: number;
    averageSeconds: number;
    p50Seconds: number;
    p95Seconds: number;
  };
}

export async function buildAnalytics(input: {
  orgId: string;
  environment: Environment;
  range?: string | null;
  since?: string | null;
  until?: string | null;
  agentId?: string | null;
}): Promise<AnalyticsResult> {
  const window = normalizeTimeWindow({ range: input.range, since: input.since, until: input.until });
  const agentId = input.agentId?.trim() || null;
  const statsRows = await db()`
    SELECT count(*)::int AS actions,
           count(*) FILTER (WHERE decision = 'allow')::int AS allowed,
           count(*) FILTER (WHERE decision = 'deny')::int AS denied,
           count(*) FILTER (WHERE outcome_status IS NOT NULL)::int AS completed,
           count(*) FILTER (WHERE outcome_status = 'failure')::int AS failed,
           count(*) FILTER (WHERE verified IS TRUE)::int AS verified,
           count(*) FILTER (WHERE payload->'outcome'->'outcome'->>'source' = 'broker_observed')::int AS broker_observed,
           count(*) FILTER (WHERE payload->'outcome'->'outcome'->>'source' = 'agent_reported')::int AS agent_reported,
           count(DISTINCT agent_id)::int AS agents,
           count(*) FILTER (WHERE policy_id IS NOT NULL AND policy_id <> '')::int AS governed,
           count(DISTINCT policy_id) FILTER (WHERE policy_id IS NOT NULL AND policy_id <> '')::int AS policies
      FROM actions
     WHERE org_id = ${input.orgId}
       AND environment_id = ${input.environment.id}
       AND created_at >= ${window.since}
       AND created_at <= ${window.until}
       AND (${agentId}::text IS NULL OR agent_id = ${agentId})
  `;
  const stats = (statsRows[0] ?? {}) as Record<string, number>;

  const reviewRows = await db()`
    SELECT count(*)::int AS total,
           count(*) FILTER (WHERE r.status = 'pending')::int AS pending
      FROM action_reviews r
      JOIN actions a ON a.action_id = r.action_id
     WHERE r.org_id = ${input.orgId}
       AND r.environment_id = ${input.environment.id}
       AND a.created_at >= ${window.since}
       AND a.created_at <= ${window.until}
  `;
  const reviews = (reviewRows[0] ?? {}) as Record<string, number>;

  const linkRows = await db()`
    SELECT count(*)::int AS count FROM verification_links
     WHERE org_id = ${input.orgId}
       AND environment_id = ${input.environment.id}
       AND revoked_at IS NULL
       AND expires_at > now()
  `;
  const packRows = await db()`
    SELECT count(*)::int AS count FROM evidence_packs
     WHERE org_id = ${input.orgId}
       AND environment_id = ${input.environment.id}
       AND status = 'ready'
  `;

  const seriesRows = await db()`
    SELECT to_char(created_at::date, 'YYYY-MM-DD') AS day,
           count(*)::int AS actions,
           count(*) FILTER (WHERE decision = 'allow')::int AS allowed,
           count(*) FILTER (WHERE decision = 'deny')::int AS denied,
           count(*) FILTER (WHERE outcome_status = 'failure')::int AS failed,
           count(*) FILTER (WHERE verified IS TRUE)::int AS verified,
           count(*) FILTER (WHERE payload->'outcome'->'outcome'->>'source' = 'broker_observed')::int AS broker_observed,
           count(*) FILTER (WHERE payload->'outcome'->'outcome'->>'source' = 'agent_reported')::int AS agent_reported
      FROM actions
     WHERE org_id = ${input.orgId}
       AND environment_id = ${input.environment.id}
       AND created_at >= ${window.since}
       AND created_at <= ${window.until}
       AND (${agentId}::text IS NULL OR agent_id = ${agentId})
     GROUP BY created_at::date
     ORDER BY created_at::date
  `;
  const days = dayKeys(window.since, window.until);
  const seriesMap = new Map((seriesRows as Array<Record<string, any>>).map((row) => [String(row.day), row]));
  const series: AnalyticsDay[] = days.map((day) => {
    const row = seriesMap.get(day);
    return {
      day,
      actions: Number(row?.actions ?? 0),
      allowed: Number(row?.allowed ?? 0),
      denied: Number(row?.denied ?? 0),
      failed: Number(row?.failed ?? 0),
      verified: Number(row?.verified ?? 0),
      brokerObserved: Number(row?.broker_observed ?? 0),
      agentReported: Number(row?.agent_reported ?? 0),
    };
  });

  const toolRows = await db()`
    SELECT tool,
           count(*)::int AS actions,
           count(*) FILTER (WHERE decision = 'allow')::int AS allowed,
           count(*) FILTER (WHERE decision = 'deny')::int AS denied,
           count(*) FILTER (WHERE outcome_status = 'failure')::int AS failed,
           count(*) FILTER (WHERE verified IS TRUE)::int AS verified
      FROM actions
     WHERE org_id = ${input.orgId}
       AND environment_id = ${input.environment.id}
       AND created_at >= ${window.since}
       AND created_at <= ${window.until}
       AND (${agentId}::text IS NULL OR agent_id = ${agentId})
     GROUP BY tool ORDER BY actions DESC LIMIT 40
  `;
  const tools: AnalyticsTool[] = (toolRows as Array<Record<string, any>>).map((row) => ({
    tool: String(row.tool),
    actions: Number(row.actions),
    allowed: Number(row.allowed),
    denied: Number(row.denied),
    failed: Number(row.failed),
    verified: Number(row.verified),
  }));

  const policyRows = await db()`
    SELECT COALESCE(NULLIF(policy_id, ''), 'ungoverned') AS policy_id,
           count(*)::int AS actions,
           count(*) FILTER (WHERE decision = 'deny')::int AS denied,
           count(*) FILTER (WHERE verified IS TRUE)::int AS verified
      FROM actions
     WHERE org_id = ${input.orgId}
       AND environment_id = ${input.environment.id}
       AND created_at >= ${window.since}
       AND created_at <= ${window.until}
       AND (${agentId}::text IS NULL OR agent_id = ${agentId})
     GROUP BY COALESCE(NULLIF(policy_id, ''), 'ungoverned')
     ORDER BY actions DESC LIMIT 20
  `;
  const policies: AnalyticsPolicy[] = (policyRows as Array<Record<string, any>>).map((row) => ({
    policyId: String(row.policy_id),
    actions: Number(row.actions),
    denied: Number(row.denied),
    verified: Number(row.verified),
  }));

  const heatRows = await db()`
    SELECT agent_id, to_char(created_at::date, 'YYYY-MM-DD') AS day,
           count(*)::int AS actions,
           count(*) FILTER (WHERE decision = 'deny')::int AS denied
      FROM actions
     WHERE org_id = ${input.orgId}
       AND environment_id = ${input.environment.id}
       AND created_at >= ${window.since}
       AND created_at <= ${window.until}
       AND (${agentId}::text IS NULL OR agent_id = ${agentId})
     GROUP BY agent_id, created_at::date
     ORDER BY agent_id, created_at::date
  `;
  const heatCells = (heatRows as Array<Record<string, any>>).map((row) => ({
    agentId: String(row.agent_id),
    day: String(row.day),
    actions: Number(row.actions),
    denied: Number(row.denied),
  }));
  const agentTotals = new Map<string, { actions: number; denied: number }>();
  for (const cell of heatCells) {
    const current = agentTotals.get(cell.agentId) ?? { actions: 0, denied: 0 };
    current.actions += cell.actions;
    current.denied += cell.denied;
    agentTotals.set(cell.agentId, current);
  }
  const heatAgents = [...agentTotals.entries()]
    .map(([agentIdValue, value]) => ({ agentId: agentIdValue, ...value }))
    .sort((a, b) => b.actions - a.actions)
    .slice(0, 8);
  const heatAgentIds = new Set(heatAgents.map((agent) => agent.agentId));

  const verificationRows = await db()`
    SELECT count(*)::int AS sample,
           COALESCE(avg(extract(epoch FROM (verified_at - created_at))), 0)::float AS average_seconds,
           COALESCE(percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM (verified_at - created_at))), 0)::float AS p50_seconds,
           COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM (verified_at - created_at))), 0)::float AS p95_seconds
      FROM actions
     WHERE org_id = ${input.orgId}
       AND environment_id = ${input.environment.id}
       AND created_at >= ${window.since}
       AND created_at <= ${window.until}
       AND verified_at IS NOT NULL
       AND (${agentId}::text IS NULL OR agent_id = ${agentId})
  `;
  const verification = (verificationRows[0] ?? {}) as Record<string, number>;

  const actions = Number(stats.actions ?? 0);
  const completed = Number(stats.completed ?? 0);
  const governed = Number(stats.governed ?? 0);
  return {
    window,
    totals: {
      actions,
      allowed: Number(stats.allowed ?? 0),
      denied: Number(stats.denied ?? 0),
      completed,
      failed: Number(stats.failed ?? 0),
      verified: Number(stats.verified ?? 0),
      brokerObserved: Number(stats.broker_observed ?? 0),
      agentReported: Number(stats.agent_reported ?? 0),
      agents: Number(stats.agents ?? 0),
      governed,
      ungoverned: Math.max(0, actions - governed),
      policies: Number(stats.policies ?? 0),
      reviews: Number(reviews.total ?? 0),
      pendingReviews: Number(reviews.pending ?? 0),
      verificationLinks: Number((linkRows[0] as Record<string, unknown> | undefined)?.count ?? 0),
      evidencePacks: Number((packRows[0] as Record<string, unknown> | undefined)?.count ?? 0),
    },
    rates: {
      allow: actions ? Number(stats.allowed ?? 0) / actions : 0,
      deny: actions ? Number(stats.denied ?? 0) / actions : 0,
      verifiedOutcome: completed ? Number(stats.verified ?? 0) / completed : 0,
      policyCoverage: actions ? governed / actions : 0,
    },
    series,
    tools,
    policies,
    heatmap: {
      agents: heatAgents,
      days,
      cells: heatCells.filter((cell) => heatAgentIds.has(cell.agentId)),
    },
    verification: {
      sample: Number(verification.sample ?? 0),
      averageSeconds: Number(verification.average_seconds ?? 0),
      p50Seconds: Number(verification.p50_seconds ?? 0),
      p95Seconds: Number(verification.p95_seconds ?? 0),
    },
  };
}
