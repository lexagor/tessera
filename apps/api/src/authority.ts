import { createHmac, timingSafeEqual } from "node:crypto";

import { env } from "./env.js";
import { uuid } from "./crypto.js";

const ISSUER = "tessera-api";
const AUDIENCE = "tessera-broker";

export interface AuthorityClaims {
  iss: string;
  aud: string;
  sub: string;
  iat: number;
  exp: number;
  jti: string;
  principal_type: "user";
  authority_ref: string;
  org_id: string;
  environment_id: string;
  agent_id: string;
  scope: "agent:authorize";
}

export interface MintAuthorityInput {
  userId: string;
  oidcSubject: string | null;
  orgId: string;
  environmentId: string;
  agentId: string;
  ttlSeconds?: number;
}

export interface MintedAuthorityToken {
  token: string;
  claims: AuthorityClaims;
  expiresAt: string;
}

function secret(): string {
  const value = env.TESSERA_AUTHORITY_HMAC_SECRET;
  if (!value) {
    throw new Error("TESSERA_AUTHORITY_HMAC_SECRET is not configured");
  }
  return value;
}

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function signature(input: string, key: string): string {
  return createHmac("sha256", key).update(input).digest("base64url");
}

function parsePart<T>(part: string): T {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as T;
}

export function authorityConfigured(): boolean {
  return Boolean(env.TESSERA_AUTHORITY_HMAC_SECRET);
}

export function mintAuthorityToken(input: MintAuthorityInput): MintedAuthorityToken {
  const now = Math.floor(Date.now() / 1000);
  const ttl = Math.min(
    Math.max(input.ttlSeconds ?? env.TESSERA_AUTHORITY_TOKEN_TTL_SECONDS, 30),
    86_400,
  );
  const claims: AuthorityClaims = {
    iss: ISSUER,
    aud: AUDIENCE,
    sub: input.userId,
    iat: now,
    exp: now + ttl,
    jti: uuid(),
    principal_type: "user",
    authority_ref: input.oidcSubject
      ? `oidc:${input.oidcSubject}`
      : `user:${input.userId}`,
    org_id: input.orgId,
    environment_id: input.environmentId,
    agent_id: input.agentId,
    scope: "agent:authorize",
  };
  const header = encode({ alg: "HS256", typ: "JWT" });
  const payload = encode(claims);
  const token = `${header}.${payload}.${signature(`${header}.${payload}`, secret())}`;
  return {
    token,
    claims,
    expiresAt: new Date(claims.exp * 1000).toISOString(),
  };
}

export function verifyAuthorityToken(
  token: string,
  expected: { orgId: string; environmentId: string; agentId: string },
): AuthorityClaims {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("authorityToken is not a JWT");
  const [headerPart, payloadPart, signaturePart] = parts;
  if (!headerPart || !payloadPart || !signaturePart) {
    throw new Error("authorityToken is not a JWT");
  }
  const header = parsePart<{ alg?: string; typ?: string }>(headerPart);
  if (header.alg !== "HS256") throw new Error("authorityToken must use HS256");
  const expectedSignature = signature(`${headerPart}.${payloadPart}`, secret());
  const actual = Buffer.from(signaturePart, "base64url");
  const wanted = Buffer.from(expectedSignature, "base64url");
  if (actual.length !== wanted.length || !timingSafeEqual(actual, wanted)) {
    throw new Error("authorityToken signature is invalid");
  }
  const claims = parsePart<AuthorityClaims>(payloadPart);
  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== ISSUER) throw new Error("authorityToken issuer is invalid");
  if (claims.aud !== AUDIENCE) throw new Error("authorityToken audience is invalid");
  if (!claims.sub) throw new Error("authorityToken subject is missing");
  if (!Number.isFinite(claims.exp) || claims.exp <= now) {
    throw new Error("authorityToken is expired");
  }
  if (claims.exp > now + 86_400) {
    throw new Error("authorityToken expiry exceeds 24 hours");
  }
  if (claims.org_id !== expected.orgId) {
    throw new Error("authorityToken belongs to a different organization");
  }
  if (claims.environment_id !== expected.environmentId) {
    throw new Error("authorityToken belongs to a different environment");
  }
  if (claims.agent_id !== expected.agentId) {
    throw new Error("authorityToken belongs to a different agent");
  }
  return claims;
}
