import { getConnInfo } from "@hono/node-server/conninfo";
import type { Context } from "hono";

import { env } from "./env.js";

function forwardedAddress(value: string | undefined): string | null {
  if (!value) return null;
  const entries = value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
  return entries.length > 0 ? (entries[entries.length - 1] ?? null) : null;
}

/** Resolve a client address without trusting spoofable headers unless explicitly configured. */
export function clientIp(c: Context): string {
  if (env.TRUST_PROXY) {
    const forwarded = forwardedAddress(c.req.header("x-forwarded-for"));
    if (forwarded) return forwarded;
    const real = c.req.header("x-real-ip")?.trim();
    if (real) return real;
  }
  try {
    return getConnInfo(c).remote.address ?? "unknown";
  } catch {
    return "unknown";
  }
}
