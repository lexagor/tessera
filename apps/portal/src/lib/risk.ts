export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface Risk {
  level: RiskLevel;
  label: string;
}

export function riskForTool(tool: string, decision?: string): Risk {
  const value = tool.toLowerCase();
  if (decision === "deny") {
    return { level: "critical", label: "Critical" };
  }
  if (value.includes("refund") || value.includes("payment") || value.includes("charge") || value.includes("delete") || value.includes("send") || value.includes("write")) {
    return { level: "high", label: "High" };
  }
  if (value.includes("create") || value.includes("update") || value.includes("patch")) {
    return { level: "medium", label: "Medium" };
  }
  return { level: "low", label: "Low" };
}

export function riskRank(level: RiskLevel): number {
  return { low: 0, medium: 1, high: 2, critical: 3 }[level];
}

export function relativeTime(value: string | null | undefined): string {
  if (!value) return "—";
  const time = new Date(value).getTime();
  if (!Number.isFinite(time)) return value;
  const delta = Math.max(0, Date.now() - time);
  const minutes = Math.floor(delta / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 14) return `${days}d ago`;
  return new Date(value).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}
