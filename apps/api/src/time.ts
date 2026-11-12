export type TimeRange = "24h" | "7d" | "14d" | "30d" | "90d" | "custom";

export interface TimeWindow {
  since: string;
  until: string;
  range: TimeRange;
  days: number;
}

const RANGE_DAYS: Record<Exclude<TimeRange, "custom">, number> = {
  "24h": 1,
  "7d": 7,
  "14d": 14,
  "30d": 30,
  "90d": 90,
};

export function parseDateParam(
  value: unknown,
  fallback: Date,
  endOfDay = false,
): Date {
  if (typeof value !== "string" || !value.trim()) return fallback;
  const trimmed = value.trim();
  const dateOnly = /^\d{4}-\d{2}-\d{2}$/.test(trimmed);
  const date = new Date(
    dateOnly ? `${trimmed}T${endOfDay ? "23:59:59.999" : "00:00:00.000"}Z` : trimmed,
  );
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid date: ${trimmed}`);
  return date;
}

export function normalizeTimeWindow(
  input: { range?: string | null; since?: string | null; until?: string | null },
  now = new Date(),
): TimeWindow {
  const requested = input.range ?? "14d";
  const range: TimeRange =
    requested in RANGE_DAYS || requested === "custom"
      ? (requested as TimeRange)
      : "14d";
  const days = range === "custom" ? 14 : RANGE_DAYS[range];
  const defaultSince = new Date(now.getTime() - days * 86_400_000);
  const since = parseDateParam(input.since, defaultSince);
  const until = parseDateParam(input.until, now, true);
  if (since > until) throw new Error("since must be before until");
  if (until.getTime() - since.getTime() > 366 * 86_400_000) {
    throw new Error("time range must be 366 days or less");
  }
  return {
    since: since.toISOString(),
    until: until.toISOString(),
    range: input.since || input.until ? "custom" : range,
    days: Math.max(1, Math.ceil((until.getTime() - since.getTime()) / 86_400_000)),
  };
}

export function dayKeys(since: string, until: string): string[] {
  const first = new Date(`${new Date(since).toISOString().slice(0, 10)}T00:00:00.000Z`);
  const last = new Date(`${new Date(until).toISOString().slice(0, 10)}T00:00:00.000Z`);
  const days: string[] = [];
  for (let cursor = first.getTime(); cursor <= last.getTime(); cursor += 86_400_000) {
    days.push(new Date(cursor).toISOString().slice(0, 10));
  }
  return days;
}
