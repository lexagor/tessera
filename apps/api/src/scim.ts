import { Hono, type Context, type MiddlewareHandler } from "hono";

import { db, withAdminContext, withOrgContext } from "./db.js";
import { randomToken, sha256, uuid } from "./crypto.js";
import { env } from "./env.js";
import { rateLimit } from "./rate-limit.js";

export type ScimRole = "admin" | "member" | "viewer";

type ScimEnv = {
  Variables: {
    scimOrgId: string;
    scimTokenId: string;
  };
};

const USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
const PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

export const scimRoutes = new Hono<ScimEnv>();

scimRoutes.use(
  "*",
  rateLimit({
    name: "SCIM",
    limit: env.RATE_LIMIT_SCIM_PER_MINUTE,
    key: (c) => `scim:${sha256(c.req.header("authorization") ?? "")}`,
  }) as unknown as MiddlewareHandler<ScimEnv>,
);

function scimError(c: Context<ScimEnv>, status: number, detail: string) {
  return c.json(
    { schemas: [ERROR_SCHEMA], detail, status: String(status) },
    status as 400,
  );
}

const requireScimToken: MiddlewareHandler<ScimEnv> = async (c, next) => {
  const auth = c.req.header("authorization") ?? "";
  const match = /^Bearer\s+(.+)$/i.exec(auth.trim());
  if (!match) return scimError(c, 401, "A SCIM bearer token is required");
  const token = await withAdminContext(async () => {
    const rows = await db()`
      SELECT t.id, t.org_id
        FROM scim_tokens t
       WHERE t.token_hash = ${sha256(match[1] ?? "")}
         AND t.revoked_at IS NULL
         AND (t.expires_at IS NULL OR t.expires_at > now())
       LIMIT 1
    `;
    const found = rows[0] as { id: string; org_id: string } | undefined;
    if (found) await db()`UPDATE scim_tokens SET last_used_at = now() WHERE id = ${found.id}`;
    return found;
  });
  if (!token) return scimError(c, 401, "Invalid or revoked SCIM token");
  c.set("scimOrgId", token.org_id);
  c.set("scimTokenId", token.id);
  return withOrgContext(token.org_id, next);
};

scimRoutes.use("*", requireScimToken);

scimRoutes.get("/ServiceProviderConfig", (c) =>
  c.json({
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    documentationUri: "https://thetessera.xyz/docs/scim.html",
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: 500 },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [
      {
        type: "oauthbearertoken",
        name: "OAuth Bearer Token",
        description: "Organization-scoped SCIM token created in Tessera Settings.",
        specUri: "https://www.rfc-editor.org/info/rfc6750",
        primary: true,
      },
    ],
  }),
);

scimRoutes.get("/ResourceTypes", (c) =>
  c.json({
    schemas: [LIST_SCHEMA],
    totalResults: 1,
    startIndex: 1,
    itemsPerPage: 1,
    Resources: [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        id: "User",
        name: "User",
        endpoint: "/Users",
        description: "Tessera workspace member",
        schema: USER_SCHEMA,
        schemaExtensions: [],
      },
    ],
  }),
);

function userResource(row: Record<string, any>, orgId: string) {
  const id = String(row.user_id ?? row.id);
  return {
    schemas: [USER_SCHEMA],
    id,
    userName: String(row.email),
    name: { formatted: row.name ? String(row.name) : undefined },
    emails: [{ value: String(row.email), primary: true, type: "work" }],
    active: true,
    roles: [{ value: String(row.role ?? "member"), primary: true }],
    meta: {
      resourceType: "User",
      created: row.created_at,
      lastModified: row.created_at,
      location: `/scim/v2/Users/${id}`,
    },
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
      organization: orgId,
    },
  };
}

function emailFromBody(body: Record<string, any>): string | null {
  const candidate =
    body.userName ??
    (Array.isArray(body.emails) ? body.emails.find((entry: any) => entry?.primary)?.value : null) ??
    (Array.isArray(body.emails) ? body.emails[0]?.value : null);
  return typeof candidate === "string" && candidate.includes("@")
    ? candidate.trim().toLowerCase()
    : null;
}

function roleFromBody(body: Record<string, any>): ScimRole {
  const raw = Array.isArray(body.roles) ? body.roles[0]?.value : body.role;
  return raw === "admin" || raw === "viewer" ? raw : "member";
}

function parseFilter(filter: string | undefined): { field: "userName" | null; value: string | null } {
  if (!filter) return { field: null, value: null };
  const match = /^\s*userName\s+eq\s+"([^"]*)"\s*$/i.exec(filter);
  if (!match) return { field: null, value: null };
  return { field: "userName", value: match[1] ?? null };
}

scimRoutes.get("/Users", async (c) => {
  const orgId = c.get("scimOrgId");
  const filter = parseFilter(c.req.query("filter"));
  if (c.req.query("filter") && !filter.field && !filter.value) {
    return scimError(c, 400, "Only userName eq \"...\" filters are supported");
  }
  const rows = await db()`
    SELECT u.id AS user_id, u.email, u.name, m.role, m.created_at
      FROM memberships m JOIN users u ON u.id = m.user_id
     WHERE m.org_id = ${orgId}
       AND (${filter.value}::text IS NULL OR lower(u.email) = lower(${filter.value}))
     ORDER BY m.created_at
  `;
  const startIndex = Math.max(1, Number(c.req.query("startIndex") ?? 1));
  const count = Math.min(500, Math.max(1, Number(c.req.query("count") ?? 100)));
  const page = rows.slice(startIndex - 1, startIndex - 1 + count);
  return c.json({
    schemas: [LIST_SCHEMA],
    totalResults: rows.length,
    startIndex,
    itemsPerPage: page.length,
    Resources: page.map((row) => userResource(row as Record<string, any>, orgId)),
  });
});

scimRoutes.get("/Users/:id", async (c) => {
  const orgId = c.get("scimOrgId");
  const rows = await db()`
    SELECT u.id AS user_id, u.email, u.name, m.role, m.created_at
      FROM memberships m JOIN users u ON u.id = m.user_id
     WHERE m.org_id = ${orgId} AND u.id = ${c.req.param("id")}
     LIMIT 1
  `;
  if (!rows[0]) return scimError(c, 404, "User not found");
  return c.json(userResource(rows[0] as Record<string, any>, orgId));
});

scimRoutes.post("/Users", async (c) => {
  const orgId = c.get("scimOrgId");
  const body = (await c.req.json().catch(() => null)) as Record<string, any> | null;
  if (!body) return scimError(c, 400, "Invalid JSON body");
  const email = emailFromBody(body);
  if (!email) return scimError(c, 400, "userName or a primary email is required");
  const role = roleFromBody(body);
  const name = typeof body.name?.formatted === "string" ? body.name.formatted.slice(0, 200) : null;

  const existing = await db()`
    SELECT id FROM users WHERE lower(email) = ${email} LIMIT 1
  `;
  const userId = (existing[0]?.id as string | undefined) ?? uuid();
  const membership = await db()`
    SELECT 1 FROM memberships WHERE org_id = ${orgId} AND user_id = ${userId} LIMIT 1
  `;
  if (membership[0]) return scimError(c, 409, "User is already a member of this workspace");

  if (!existing[0]) {
    await db()`
      INSERT INTO users (id, email, name)
      VALUES (${userId}, ${email}, ${name})
    `;
  } else if (name) {
    await db()`UPDATE users SET name = coalesce(name, ${name}) WHERE id = ${userId}`;
  }
  await db()`
    INSERT INTO memberships (org_id, user_id, role)
    VALUES (${orgId}, ${userId}, ${role})
  `;
  const rows = await db()`
    SELECT u.id AS user_id, u.email, u.name, m.role, m.created_at
      FROM memberships m JOIN users u ON u.id = m.user_id
     WHERE m.org_id = ${orgId} AND m.user_id = ${userId}
  `;
  c.header("location", `/scim/v2/Users/${userId}`);
  return c.json(userResource(rows[0] as Record<string, any>, orgId), 201);
});

scimRoutes.patch("/Users/:id", async (c) => {
  const orgId = c.get("scimOrgId");
  const userId = c.req.param("id");
  const body = (await c.req.json().catch(() => null)) as Record<string, any> | null;
  if (!body?.schemas?.includes(PATCH_SCHEMA) && !Array.isArray(body?.Operations) && !Array.isArray(body?.operations)) {
    return scimError(c, 400, "Expected a SCIM PatchOp body");
  }
  const operations = (body?.Operations ?? body?.operations ?? []) as Array<Record<string, any>>;
  const membership = await db()`
    SELECT u.id AS user_id, u.email, u.name, m.role, m.created_at
      FROM memberships m JOIN users u ON u.id = m.user_id
     WHERE m.org_id = ${orgId} AND m.user_id = ${userId}
     LIMIT 1
  `;
  if (!membership[0]) return scimError(c, 404, "User not found");

  for (const operation of operations) {
    const op = String(operation.op ?? "").toLowerCase();
    if (op !== "replace" && op !== "add") continue;
    const path = String(operation.path ?? "").toLowerCase();
    const value = operation.value;
    if (path === "active" || (value && typeof value === "object" && "active" in value)) {
      const active = path === "active" ? value === true || value === "true" : value.active === true;
      if (!active) {
        await db()`DELETE FROM memberships WHERE org_id = ${orgId} AND user_id = ${userId}`;
        return c.json({ ...userResource(membership[0] as Record<string, any>, orgId), active: false });
      }
    }
    if (path === "name.formatted" || (path === "" && value?.name?.formatted)) {
      const name = String(path === "name.formatted" ? value : value.name.formatted).slice(0, 200);
      await db()`UPDATE users SET name = ${name} WHERE id = ${userId}`;
    }
    if (path === "roles" || path === "role") {
      const role = roleFromBody({ roles: Array.isArray(value) ? value : [{ value }] });
      await db()`
        UPDATE memberships SET role = ${role}
         WHERE org_id = ${orgId} AND user_id = ${userId}
      `;
    }
  }
  const rows = await db()`
    SELECT u.id AS user_id, u.email, u.name, m.role, m.created_at
      FROM memberships m JOIN users u ON u.id = m.user_id
     WHERE m.org_id = ${orgId} AND m.user_id = ${userId}
  `;
  return c.json(userResource(rows[0] as Record<string, any>, orgId));
});

scimRoutes.delete("/Users/:id", async (c) => {
  const orgId = c.get("scimOrgId");
  const result = await db()`
    DELETE FROM memberships
     WHERE org_id = ${orgId} AND user_id = ${c.req.param("id")}
  `;
  if (result.count === 0) return scimError(c, 404, "User not found");
  return c.body(null, 204);
});

export function newScimToken(): { token: string; hash: string } {
  const token = `scim_${randomToken(32)}`;
  return { token, hash: sha256(token) };
}
