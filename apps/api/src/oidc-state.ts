import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import { env } from "./env.js";

const MAX_AGE_SECONDS = 600;
let developmentSecret: string | null = null;

export interface OidcState {
  state: string;
  nonce: string;
  verifier: string;
  issuedAt: number;
}

function secret(): string {
  if (env.OIDC_STATE_SECRET) return env.OIDC_STATE_SECRET;
  if (env.CONTROL_PLANE_ENC_KEY) return env.CONTROL_PLANE_ENC_KEY;
  if (env.TESSERA_AUTHORITY_HMAC_SECRET) return env.TESSERA_AUTHORITY_HMAC_SECRET;
  developmentSecret ??= randomBytes(32).toString("hex");
  return developmentSecret;
}

function signature(payload: string): string {
  return createHmac("sha256", secret()).update(payload).digest("base64url");
}

export function encodeOidcState(input: { state: string; nonce: string; verifier: string }): string {
  const payload = Buffer.from(
    JSON.stringify({
      version: 1,
      state: input.state,
      nonce: input.nonce,
      verifier: input.verifier,
      issuedAt: Math.floor(Date.now() / 1000),
    }),
  ).toString("base64url");
  return `${payload}.${signature(payload)}`;
}

export function decodeOidcState(raw: string): OidcState | null {
  const [payload, supplied, extra] = raw.split(".");
  if (!payload || !supplied || extra) return null;

  const expected = signature(payload);
  const suppliedBuffer = Buffer.from(supplied);
  const expectedBuffer = Buffer.from(expected);
  if (
    suppliedBuffer.length !== expectedBuffer.length ||
    !timingSafeEqual(suppliedBuffer, expectedBuffer)
  ) {
    return null;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  const value = parsed as Record<string, unknown>;
  if (value.version !== 1) return null;
  if (
    typeof value.state !== "string" ||
    typeof value.nonce !== "string" ||
    typeof value.verifier !== "string" ||
    typeof value.issuedAt !== "number"
  ) {
    return null;
  }
  const now = Math.floor(Date.now() / 1000);
  if (value.issuedAt > now + 30 || now - value.issuedAt > MAX_AGE_SECONDS) return null;
  return {
    state: value.state,
    nonce: value.nonce,
    verifier: value.verifier,
    issuedAt: value.issuedAt,
  };
}
