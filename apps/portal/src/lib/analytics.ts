import { riskForTool, riskRank, type RiskLevel } from "./risk";

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
  window: { since: string; until: string; range: string; days: number };
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

export interface NotificationItem {
  id: string;
  severity: "critical" | "warning" | "info";
  title: string;
  detail: string;
  href: string;
  count: number;
  createdAt: string | null;
}

export interface SearchResult {
  actions: Array<{ actionId: string; tool: string; agentId: string; decision: string; createdAt: string }>;
  agents: Array<{ agentId: string; actions: number; lastSeen: string }>;
  policies: Array<{ id: string; name: string; version: number; mode?: string }>;
  verificationLinks: Array<{ id: string; actionId: string; tool: string; createdAt: string }>;
}

export function riskDistribution(tools: AnalyticsTool[]): Record<RiskLevel, number> {
  const distribution: Record<RiskLevel, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  for (const tool of tools) {
    const allowed = Math.max(0, tool.actions - tool.denied);
    const level = riskForTool(tool.tool).level;
    distribution[level] += allowed;
    distribution.critical += tool.denied;
  }
  return distribution;
}

export function riskOrder(): RiskLevel[] {
  return ["critical", "high", "medium", "low"];
}

export function riskTotal(distribution: Record<RiskLevel, number>): number {
  return Object.values(distribution).reduce((total, value) => total + value, 0);
}

export function topRiskLevel(distribution: Record<RiskLevel, number>): RiskLevel {
  return [...riskOrder()].sort((a, b) => distribution[b] - distribution[a])[0] ?? "low";
}

export function riskLabel(level: RiskLevel): string {
  return level.slice(0, 1).toUpperCase() + level.slice(1);
}

export function chartMax(values: number[]): number {
  return Math.max(1, ...values);
}

export { riskRank };
