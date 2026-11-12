import { db } from "./db.js";

export interface Plan {
  name: string;
  actionsPerMonth: number;
  environments: number;
  members: number;
}

export const PLANS: Record<string, Plan> = {
  developer: { name: "developer", actionsPerMonth: 1_000, environments: 1, members: 2 },
  team: { name: "team", actionsPerMonth: 250_000, environments: 3, members: 10 },
  growth: { name: "growth", actionsPerMonth: 1_000_000, environments: 10, members: 50 },
  enterprise: {
    name: "enterprise",
    actionsPerMonth: 5_000_000,
    environments: 100,
    members: 500,
  },
};

const FALLBACK_PLAN: Plan = {
  name: "team",
  actionsPerMonth: 250_000,
  environments: 3,
  members: 10,
};

export function planFor(name: string): Plan {
  return PLANS[name] ?? FALLBACK_PLAN;
}

export async function monthlyActionCount(orgId: string): Promise<number> {
  const rows = await db()`
    SELECT coalesce(sum(actions), 0)::int AS total
      FROM usage_daily
     WHERE org_id = ${orgId}
       AND day >= date_trunc('month', current_date)
  `;
  return Number(rows[0]?.total ?? 0);
}

export async function environmentCount(orgId: string): Promise<number> {
  const rows = await db()`
    SELECT count(*)::int AS total FROM environments WHERE org_id = ${orgId}
  `;
  return Number(rows[0]?.total ?? 0);
}
