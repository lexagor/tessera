import { createHmac, timingSafeEqual } from "node:crypto";

import { env } from "./env.js";
import { uuid } from "./crypto.js";

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
  tenant: string;
  scope: "agent:authorize";
}

export interface MintAuthorityInput {
  userId: string;
  oidcSubject: string | null;
  orgId: string;
  environmentId: string;
  agentId: string;
  tenant: string;
  ttlSeconds?: number;
}

export interface MintedAuthorityToken {
  token: string;
  claims: AuthorityClaims;
  expiresAt: string;
}

interface AuthorityKey {
  kid: string;
  secret: string;
}

const mintWindows = new Map<string, { count: number; resetAt: number }>();

export function allowAuthorityMint(key: string, perMinute: number): boolean {
  const now = Date.now();
  if (mintWindows.size > 10_000) {
    for (const [entry, window] of mintWindows) {
      if (window.resetAt <= now) mintWindows.delete(entry);
    }
  }
  const window = mintWindows.get(key);
  if (!window || window.resetAt <= now) {
    mintWindows.set(key, { count: 1, resetAt: now + 60_000 });
    return true;
  }
  if (window.count >= perMinute) return false;
  window.count += 1;
  return true;
}

function keyring(): AuthorityKey[] {
  const current = env.TESSERA_AUTHORITY_HMAC_SECRET;
  if (!current) return [];
  const keys: AuthorityKey[] = [
    { kid: env.TESSERA_AUTHORITY_KID, secret: current },
  ];
  const previous = env.TESSERA_AUTHORITY_HMAC_SECRET_PREVIOUS;
  if (previous) {
    if (env.TESSERA_AUTHORITY_PREVIOUS_KID === env.TESSERA_AUTHORITY_KID) {
      throw new Error("TESSERA_AUTHORITY_PREVIOUS_KID must differ from TESSERA_AUTHORITY_KID");
    }
    keys.push({ kid: env.TESSERA_AUTHORITY_PREVIOUS_KID, secret: previous });
  }
  return keys;
}

function currentKey(): AuthorityKey {
  const key = keyring()[0];
  if (!key) throw new Error("TESSERA_AUTHORITY_HMAC_SECRET is not configured");
  return key;
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
  const key = currentKey();
  const claims: AuthorityClaims = {
    iss: env.TESSERA_AUTHORITY_ISSUER,
    aud: env.TESSERA_AUTHORITY_AUDIENCE,
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
    tenant: input.tenant,
    scope: "agent:authorize",
  };
  const header = encode({ alg: "HS256", typ: "JWT", kid: key.kid });
  const payload = encode(claims);
  const token = `${header}.${payload}.${signature(`${header}.${payload}`, key.secret)}`;
  return {
    token,
    claims,
    expiresAt: new Date(claims.exp * 1000).toISOString(),
  };
}

export function verifyAuthorityToken(
  token: string,
  expected: { tenant: string; orgId: string; environmentId: string; agentId: string },
): AuthorityClaims {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("authorityToken is not a JWT");
  const [headerPart, payloadPart, signaturePart] = parts;
  if (!headerPart || !payloadPart || !signaturePart) {
    throw new Error("authorityToken is not a JWT");
  }
  const header = parsePart<{ alg?: string; typ?: string; kid?: string }>(headerPart);
  if (header.alg !== "HS256") throw new Error("authorityToken must use HS256");
  const candidates = header.kid
    ? keyring().filter((key) => key.kid === header.kid)
    : keyring();
  if (candidates.length === 0) throw new Error("authorityToken uses an unknown key id");

  const actual = Buffer.from(signaturePart, "base64url");
  const verified = candidates.some((key) => {
    const wanted = Buffer.from(
      signature(`${headerPart}.${payloadPart}`, key.secret),
      "base64url",
    );
    return actual.length === wanted.length && timingSafeEqual(actual, wanted);
  });
  if (!verified) throw new Error("authorityToken signature is invalid");

  const claims = parsePart<AuthorityClaims>(payloadPart);
  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== env.TESSERA_AUTHORITY_ISSUER) {
    throw new Error("authorityToken issuer is invalid");
  }
  if (claims.aud !== env.TESSERA_AUTHORITY_AUDIENCE) {
    throw new Error("authorityToken audience is invalid");
  }
  if (!claims.sub) throw new Error("authorityToken subject is missing");
  if (!claims.jti || claims.jti.length > 256) {
    throw new Error("authorityToken jti is missing or too long");
  }
  if (!Number.isFinite(claims.exp) || claims.exp <= now) {
    throw new Error("authorityToken is expired");
  }
  if (claims.exp > now + 86_400) {
    throw new Error("authorityToken expiry exceeds 24 hours");
  }
  if (Number.isFinite(claims.iat) && claims.iat > now + 300) {
    throw new Error("authorityToken iat is in the future");
  }
  if (claims.tenant !== expected.tenant) {
    throw new Error("authorityToken belongs to a different tenant");
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
