import { env, isProduction } from "./env.js";

export function trustedOrigins(): Set<string> {
  const origins = new Set<string>();
  try {
    origins.add(new URL(env.PUBLIC_BASE_URL).origin);
  } catch {
    // Configuration validation catches malformed production URLs.
  }
  for (const value of (process.env.TRUSTED_ORIGINS ?? "").split(",")) {
    const trimmed = value.trim();
    if (!trimmed) continue;
    try {
      origins.add(new URL(trimmed).origin);
    } catch {
      // Ignore malformed optional entries; they cannot authorize a request.
    }
  }
  return origins;
}

/** Pure guard for cookie-authenticated writes. Missing Origin is rejected in production. */
export function trustedWriteOrigin(
  origin: string | undefined,
  options: { strict?: boolean; allowedOrigins?: Iterable<string> } = {},
): boolean {
  const strict = options.strict ?? isProduction;
  if (!origin) return !strict;
  if (origin === "null") return false;
  let normalized: string;
  try {
    normalized = new URL(origin).origin;
  } catch {
    return false;
  }
  const allowed = new Set(options.allowedOrigins ?? trustedOrigins());
  return allowed.has(normalized);
}
