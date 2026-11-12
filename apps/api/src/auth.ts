import type { Context, MiddlewareHandler } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";

import { uuid, randomToken, sha256, slugify } from "./crypto.js";
import { db } from "./db.js";
import { cookieSecure, env } from "./env.js";
import type { Org, Role, SessionContext, User, Variables } from "./types.js";

export type AppEnv = { Variables: Variables };

const OIDC_COOKIE = "tessera_oidc";

function sessionTtlSeconds(): number {
  return Math.max(1, env.SESSION_TTL_DAYS) * 86_400;
}

export async function createSession(
  userId: string,
  orgId: string | null,
): Promise<{ token: string; id: string }> {
  const token = randomToken(32);
  const id = uuid();
  await db()`DELETE FROM sessions WHERE expires_at < now()`;
  await db()`
    INSERT INTO sessions (id, user_id, org_id, token_hash, expires_at)
    VALUES (${id}, ${userId}, ${orgId}, ${sha256(token)}, now() + (${sessionTtlSeconds()} || ' seconds')::interval)
  `;
  return { token, id };
}

export function setSessionCookie(c: Context<AppEnv>, token: string): void {
  setCookie(c, env.SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    secure: cookieSecure,
    sameSite: "Lax",
    path: "/",
    maxAge: sessionTtlSeconds(),
  });
}

export function clearSessionCookie(c: Context<AppEnv>): void {
  deleteCookie(c, env.SESSION_COOKIE_NAME, { path: "/" });
}

export async function destroySession(c: Context<AppEnv>): Promise<void> {
  const token = getCookie(c, env.SESSION_COOKIE_NAME);
  if (token) {
    await db()`DELETE FROM sessions WHERE token_hash = ${sha256(token)}`;
  }
  clearSessionCookie(c);
}

async function loadSession(c: Context<AppEnv>): Promise<SessionContext | null> {
  const token = getCookie(c, env.SESSION_COOKIE_NAME);
  if (!token) return null;
  const rows = await db()`
    SELECT
      s.id AS session_id,
      s.org_id AS session_org_id,
      u.id AS user_id,
      u.email,
      u.name,
      u.oidc_subject
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ${sha256(token)} AND s.expires_at > now()
    LIMIT 1
  `;
  const row = rows[0];
  if (!row) return null;
  const user: User = {
    id: row.user_id as string,
    email: row.email as string,
    name: (row.name as string | null) ?? null,
    oidc_subject: (row.oidc_subject as string | null) ?? null,
  };
  let orgId = row.session_org_id as string | null;
  let role: Role | null = null;
  if (orgId) {
    const membership = await db()`
      SELECT role FROM memberships WHERE org_id = ${orgId} AND user_id = ${user.id}
    `;
    role = (membership[0]?.role as Role | undefined) ?? null;
  }
  if (!orgId || !role) {
    const membership = await db()`
      SELECT org_id, role FROM memberships WHERE user_id = ${user.id} ORDER BY created_at LIMIT 1
    `;
    if (membership[0]) {
      orgId = membership[0].org_id as string;
      role = membership[0].role as Role;
    }
  }
  if (!orgId || !role) return null;
  const orgRows = await db()`
    SELECT id, name, slug, plan FROM orgs WHERE id = ${orgId}
  `;
  const org = orgRows[0] as unknown as Org | undefined;
  if (!org) return null;
  await db()`
    UPDATE sessions
       SET last_seen_at = now(), org_id = coalesce(org_id, ${org.id})
     WHERE id = ${row.session_id as string}
  `;
  return {
    sessionId: row.session_id as string,
    user,
    org,
    role,
  };
}

export const requireSession: MiddlewareHandler<AppEnv> = async (c, next) => {
  const session = await loadSession(c);
  if (!session) {
    return c.json(
      { error: { code: "unauthorized", message: "Sign in to continue" } },
      401,
    );
  }
  c.set("session", session);
  await next();
};

export function requireRole(...roles: Role[]): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const session = c.get("session");
    if (!roles.includes(session.role)) {
      return c.json(
        { error: { code: "forbidden", message: "Insufficient role" } },
        403,
      );
    }
    await next();
  };
}

export async function findOrCreateUser(input: {
  email: string;
  name?: string | null;
  subject?: string | null;
}): Promise<User> {
  const email = input.email.trim().toLowerCase();
  const rows = await db()`
    INSERT INTO users (id, email, name, oidc_subject)
    VALUES (${uuid()}, ${email}, ${input.name ?? null}, ${input.subject ?? null})
    ON CONFLICT (email) DO UPDATE SET
      name = coalesce(EXCLUDED.name, users.name),
      oidc_subject = coalesce(EXCLUDED.oidc_subject, users.oidc_subject)
    RETURNING id, email, name, oidc_subject
  `;
  return rows[0] as unknown as User;
}

async function uniqueOrgSlug(base: string): Promise<string> {
  const root = slugify(base);
  for (let index = 0; index < 100; index += 1) {
    const candidate = index === 0 ? root : `${root}-${index + 1}`;
    const existing = await db()`SELECT 1 FROM orgs WHERE slug = ${candidate}`;
    if (existing.length === 0) return candidate;
  }
  return `${root}-${Date.now()}`;
}

export async function createOrgForUser(user: User, name?: string): Promise<Org> {
  const orgName = name?.trim() || `${user.name || user.email.split("@")[0]}'s workspace`;
  const slug = await uniqueOrgSlug(orgName);
  const id = uuid();
  const rows = await db()`
    INSERT INTO orgs (id, name, slug) VALUES (${id}, ${orgName}, ${slug})
    RETURNING id, name, slug, plan
  `;
  await db()`
    INSERT INTO memberships (org_id, user_id, role) VALUES (${id}, ${user.id}, 'owner')
  `;
  return rows[0] as unknown as Org;
}

export async function findMembership(userId: string): Promise<{ org: Org; role: Role } | null> {
  const rows = await db()`
    SELECT o.id, o.name, o.slug, o.plan, m.role
      FROM memberships m
      JOIN orgs o ON o.id = m.org_id
     WHERE m.user_id = ${userId}
     ORDER BY m.created_at
     LIMIT 1
  `;
  if (!rows[0]) return null;
  return {
    org: {
      id: rows[0].id as string,
      name: rows[0].name as string,
      slug: rows[0].slug as string,
      plan: rows[0].plan as string,
    },
    role: rows[0].role as Role,
  };
}

export async function acceptInvitesForEmail(user: User): Promise<void> {
  const invites = await db()`
    SELECT id, org_id, role
      FROM invites
     WHERE lower(email) = ${user.email.toLowerCase()}
       AND accepted_at IS NULL
       AND expires_at > now()
     ORDER BY created_at
  `;
  for (const invite of invites) {
    await db()`
      INSERT INTO memberships (org_id, user_id, role)
      VALUES (${invite.org_id as string}, ${user.id}, ${invite.role as Role})
      ON CONFLICT (org_id, user_id) DO NOTHING
    `;
    await db()`UPDATE invites SET accepted_at = now() WHERE id = ${invite.id as string}`;
  }
}

export async function upsertOidcUser(input: {
  email: string;
  name?: string | null;
  subject?: string | null;
}): Promise<User> {
  const user = await findOrCreateUser(input);
  await acceptInvitesForEmail(user);
  const membership = await findMembership(user.id);
  if (!membership) await createOrgForUser(user);
  return user;
}

export function oidcCookieOptions() {
  return {
    httpOnly: true,
    secure: cookieSecure,
    sameSite: "Lax" as const,
    path: "/",
    maxAge: 600,
  };
}

export { OIDC_COOKIE };
