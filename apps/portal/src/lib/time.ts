export type TimeRange = "24h" | "7d" | "14d" | "30d" | "90d";

export const TIME_RANGES: Array<{ id: TimeRange; label: string }> = [
  { id: "24h", label: "24h" },
  { id: "7d", label: "7d" },
  { id: "14d", label: "14d" },
  { id: "30d", label: "30d" },
  { id: "90d", label: "90d" },
];

const RANGE_DAYS: Record<TimeRange, number> = {
  "24h": 1,
  "7d": 7,
  "14d": 14,
  "30d": 30,
  "90d": 90,
};

export function isTimeRange(value: string | null): value is TimeRange {
  return value === "24h" || value === "7d" || value === "14d" || value === "30d" || value === "90d";
}

export function rangeWindow(range: TimeRange, now = new Date()): { since: string; until: string; days: number } {
  const days = RANGE_DAYS[range];
  return {
    since: new Date(now.getTime() - days * 86_400_000).toISOString(),
    until: now.toISOString(),
    days,
  };
}

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "0s";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}
