import { Hono } from "hono";
import {
  buildAgentReceipt,
  canonicalAgentReceipt,
  requestTrustedTimestamp,
  signAgentReceipt,
} from "@tessera/agent-receipts";
import type { ReceiptV2 } from "@tessera-verify/receipt-schema";
import { getCookie } from "hono/cookie";
import { z } from "zod";

import { audit } from "./audit.js";
import {
  allowAuthorityMint,
  authorityConfigured,
  mintAuthorityToken,
  verifyAuthorityToken,
} from "./authority.js";
import { persistAction, persistOutcome } from "./actions.js";
import { buildAnalytics } from "./analytics.js";
import { buildNotifications } from "./notifications.js";
import { searchResources } from "./search.js";
import { rateLimit } from "./rate-limit.js";
import { parseDateParam } from "./time.js";
import {
  type AppEnv,
  createOrgForUser,
  findMembership,
  requireRole,
  requireSession,
  sessionCookieName,
} from "./auth.js";
import * as broker from "./broker.js";
import { clientIp } from "./client-ip.js";
import { trustedWriteOrigin } from "./csrf.js";
import {
  encryptSecret,
  keyPrefix,
  newAgentKey,
  randomToken,
  sha256,
  slugify,
  uuid,
} from "./crypto.js";
import { db } from "./db.js";
import { env, verifyBaseUrl } from "./env.js";
import { evidenceStorage } from "./evidence-storage.js";
import { deletionRequestEmail, inviteEmail, sendEmail } from "./email.js";
import {
  IntegrationError,
  PROVIDERS,
  createIntegration,
  listIntegrations,
  rotateIntegration,
  testIntegration,
} from "./integrations.js";
import {
  buildEvidenceSummary,
  normalizeEvidenceFilters,
  type EvidencePackSummary,
} from "./evidence.js";
import { renderEvidenceReport } from "./evidence-report.js";
import type { Environment, SessionContext } from "./types.js";
import { WEBHOOK_EVENTS, createWebhookEndpoint, emitWebhook } from "./webhooks.js";
import { environmentCount, monthlyActionCount, planFor } from "./plans.js";
import { getBillingState, getStripe, priceForPlan, setStripeCustomer } from "./billing.js";

export const routes = new Hono<AppEnv>();

const writeRateLimit = rateLimit({
  name: "write",
  limit: env.RATE_LIMIT_WRITE_PER_MINUTE,
  key: (c) => {
    const session = getCookie(c, sessionCookieName());
    if (session) return `session:${sha256(session)}`;
    const apiKey = c.req.header("x-api-key") || c.req.header("authorization");
    if (apiKey) return `agent:${sha256(apiKey)}`;
    return `ip:${clientIp(c)}`;
  },
});

const publicRateLimit = rateLimit({
  name: "public",
  limit: env.RATE_LIMIT_PUBLIC_PER_MINUTE,
  key: (c) => `public:${clientIp(c)}`,
});

routes.use("/v1/*", async (c, next) => {
  if (c.req.method === "GET" || c.req.method === "HEAD") return next();
  return writeRateLimit(c, next);
});

routes.use("/v1/public/*", publicRateLimit);

function fail(c: any, status: number, code: string, message: string) {
  return c.json({ error: { code, message } }, status);
}

function session(c: any): SessionContext {
  return c.get("session");
}

async function getEnvironment(
  orgId: string,
  id: string,
): Promise<(Environment & { broker_key_enc: string | null; broker_key_id: string | null }) | null> {
  const rows = await db()`
    SELECT id, org_id, name, slug, broker_tenant, broker_key_enc, broker_key_id
      FROM environments WHERE id = ${id} AND org_id = ${orgId}
  `;
  return (
    (rows[0] as unknown as Environment & {
      broker_key_enc: string | null;
      broker_key_id: string | null;
    }) ?? null
  );
}

async function currentEnvironment(
  c: any,
  s: SessionContext,
): Promise<(Environment & { broker_key_enc: string | null; broker_key_id: string | null }) | null> {
  const requested = c.req.query("environmentId");
  if (requested) return getEnvironment(s.org.id, requested);
  const rows = await db()`
    SELECT id, org_id, name, slug, broker_tenant, broker_key_enc, broker_key_id
      FROM environments WHERE org_id = ${s.org.id} ORDER BY created_at LIMIT 1
  `;
  return (
    (rows[0] as unknown as Environment & {
      broker_key_enc: string | null;
      broker_key_id: string | null;
    }) ?? null
  );
}

function requestBody(c: any): Promise<unknown> {
  return c.req.json().catch(() => ({}));
}

// ── Public verification ─────────────────────────────────────────────────────

routes.get("/v1/public/verify/:token", async (c) => {
  const token = c.req.param("token");
  const rows = await db()`
    SELECT vl.id, vl.expires_at, vl.revoked_at, a.payload
      FROM verification_links vl
      JOIN actions a ON a.action_id = vl.action_id
     WHERE vl.token_hash = ${sha256(token)}
     LIMIT 1
  `;
  const link = rows[0];
  if (!link || link.revoked_at || new Date(link.expires_at as string) <= new Date()) {
    return fail(c, 404, "not_found", "Verification link is invalid or expired");
  }
  await db()`UPDATE verification_links SET view_count = view_count + 1 WHERE id = ${link.id as string}`;
  const payload = link.payload as {
    authorization?: unknown;
    outcome?: unknown;
  };
  const authorization = payload.authorization as Parameters<typeof broker.verifyRecord>[0];
  if (!authorization) return fail(c, 404, "not_found", "Action record is missing");
  const outcome = (payload.outcome as Parameters<typeof broker.verifyRecord>[1]) ?? null;
  let verification: Awaited<ReturnType<typeof broker.verifyRecord>>;
  let domain: Awaited<ReturnType<typeof broker.verifyDomain>>["domain"] | null = null;
  let signer: string | null = null;
  try {
    const verifiedDomain = await broker.verifyDomain();
    domain = verifiedDomain.domain;
    signer = verifiedDomain.signer;
    verification = await broker.verifyRecord(authorization, outcome);
  } catch {
    verification = { valid: false, errors: ["verification service unavailable"] };
  }
  return c.json({
    expiresAt: link.expires_at,
    domain,
    signer,
    verification,
    records: { authorization, outcome },
  });
});

// ── Public evidence reviewer links ──────────────────────────────────────────

async function sharedEvidencePack(token: string): Promise<Record<string, any> | null> {
  const rows = await db()`
    SELECT ep.id, ep.status, ep.object_key, ep.summary, ep.created_at, ep.expires_at,
           ep.share_expires_at, e.name AS environment_name, o.name AS org_name
      FROM evidence_packs ep
      JOIN environments e ON e.id = ep.environment_id
      JOIN orgs o ON o.id = ep.org_id
     WHERE ep.share_token_hash = ${sha256(token)}
       AND ep.share_expires_at IS NOT NULL
       AND ep.share_expires_at > now()
       AND ep.status = 'ready'
     LIMIT 1
  `;
  return (rows[0] as Record<string, any> | undefined) ?? null;
}

routes.get("/v1/public/evidence/:token", async (c) => {
  const pack = await sharedEvidencePack(c.req.param("token"));
  if (!pack) return fail(c, 404, "not_found", "Reviewer link is invalid or expired");
  const summary = pack.summary as EvidencePackSummary;
  if (!summary || summary.version !== 1) {
    return fail(c, 409, "rebuild_required", "This pack predates reviewer reports; rebuild it");
  }
  c.header("x-robots-tag", "noindex");
  return c.json({
    pack: {
      id: pack.id,
      createdAt: pack.created_at,
      expiresAt: pack.expires_at,
      shareExpiresAt: pack.share_expires_at,
      summary,
    },
    org: { name: pack.org_name },
    environment: { name: pack.environment_name },
    downloadUrl: `/v1/public/evidence/${encodeURIComponent(c.req.param("token"))}/download`,
    reportUrl: `/v1/public/evidence/${encodeURIComponent(c.req.param("token"))}/report`,
    verifyUrl: verifyBaseUrl,
    securityContact: "security@thetessera.xyz",
  });
});

routes.get("/v1/public/evidence/:token/download", async (c) => {
  const pack = await sharedEvidencePack(c.req.param("token"));
  if (!pack?.object_key) return fail(c, 404, "not_found", "Reviewer link is invalid or expired");
  let file: Uint8Array;
  try {
    file = await evidenceStorage().get(pack.object_key as string);
  } catch {
    return fail(c, 404, "not_found", "Evidence pack not found");
  }
  return new Response(file, {
    status: 200,
    headers: {
      "content-type": "application/gzip",
      "content-disposition": `attachment; filename="tessera-evidence-${pack.id}.tar.gz"`,
      "cache-control": "no-store",
      "x-robots-tag": "noindex",
    },
  });
});

routes.get("/v1/public/evidence/:token/report", async (c) => {
  const pack = await sharedEvidencePack(c.req.param("token"));
  if (!pack) return fail(c, 404, "not_found", "Reviewer link is invalid or expired");
  const summary = pack.summary as EvidencePackSummary;
  if (!summary || summary.version !== 1) {
    return fail(c, 409, "rebuild_required", "This pack predates reviewer reports; rebuild it");
  }
  const html = renderEvidenceReport(summary, {
    id: String(pack.id),
    createdAt: String(pack.created_at),
    expiresAt: pack.expires_at ? String(pack.expires_at) : null,
  });
  return new Response(html, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "content-disposition": `attachment; filename="tessera-evidence-${pack.id}.html"`,
      "cache-control": "no-store",
      "x-robots-tag": "noindex",
    },
  });
});

// ── Auth-protected control plane ────────────────────────────────────────────

routes.use("/v1/*", async (c, next) => {
  if (c.req.method !== "GET" && c.req.method !== "HEAD") {
    const origin = c.req.header("origin");
    const trusted = trustedWriteOrigin(origin);
    const hasSessionCookie = Boolean(getCookie(c, sessionCookieName()));
    if ((origin && !trusted) || (hasSessionCookie && !trusted)) {
      return fail(c, 403, "forbidden", "Cross-origin write rejected");
    }
  }
  await next();
});

routes.use("/v1/*", async (c, next) => {
  // Agent hot-path endpoints authenticate with an agent API key, not a portal session.
  if (["/v1/authorize", "/v1/record", "/v1/proxy"].includes(c.req.path)) {
    return next();
  }
  return requireSession(c, next);
});

routes.get("/v1/me", async (c) => {
  const s = session(c);
  const environments = await db()`
    SELECT id, name, slug, broker_tenant
      FROM environments WHERE org_id = ${s.org.id} ORDER BY created_at
  `;
  return c.json({
    user: s.user,
    org: s.org,
    role: s.role,
    environments,
  });
});

routes.patch("/v1/org", requireRole("owner", "admin"), async (c) => {
  const s = session(c);
  const body = z.object({ name: z.string().min(1).max(128) }).safeParse(await requestBody(c));
  if (!body.success) return fail(c, 400, "invalid_request", "Invalid organization name");
  const rows = await db()`
    UPDATE orgs SET name = ${body.data.name} WHERE id = ${s.org.id}
    RETURNING id, name, slug, plan
  `;
  await audit({
    orgId: s.org.id,
    actorUserId: s.user.id,
    action: "org.updated",
    target: s.org.id,
    details: { name: body.data.name },
  });
  return c.json(rows[0]);
});

routes.get("/v1/org/export", requireRole("owner", "admin"), async (c) => {
  const s = session(c);
  const [orgRows, members, invites, environments, agents, actions, auditRows, usage, webhookRows] =
    await Promise.all([
      db()`
        SELECT id, name, slug, plan, retention_days, deletion_requested_at, deletion_scheduled_for, created_at
          FROM orgs WHERE id = ${s.org.id}
      `,
      db()`
        SELECT u.id, u.email, u.name, m.role, m.created_at
          FROM memberships m JOIN users u ON u.id = m.user_id
         WHERE m.org_id = ${s.org.id} ORDER BY m.created_at
      `,
      db()`
        SELECT id, email, role, expires_at, accepted_at, created_at
          FROM invites WHERE org_id = ${s.org.id} ORDER BY created_at DESC
      `,
      db()`
        SELECT id, name, slug, broker_tenant, created_at
          FROM environments WHERE org_id = ${s.org.id} ORDER BY created_at
      `,
      db()`
        SELECT a.id, a.environment_id, a.agent_id, a.name, a.created_at, a.last_seen_at
          FROM agents a JOIN environments e ON e.id = a.environment_id
         WHERE e.org_id = ${s.org.id} ORDER BY a.created_at
      `,
      db()`
        SELECT action_id, environment_id, agent_id, principal_id, tool, decision, outcome_status,
               policy_id, policy_version, policy_hash, credential_issuer, credential_thumbprint,
               receipt_id, outcome_receipt_id, created_at, completed_at, verified, payload
          FROM actions WHERE org_id = ${s.org.id}
         ORDER BY created_at DESC LIMIT 10000
      `,
      db()`
        SELECT id, actor_user_id, actor_type, action, target, details, created_at
          FROM audit_log WHERE org_id = ${s.org.id}
         ORDER BY created_at DESC LIMIT 10000
      `,
      db()`
        SELECT environment_id, day, actions, allowed, denied
          FROM usage_daily WHERE org_id = ${s.org.id} ORDER BY day DESC LIMIT 3660
      `,
      db()`
        SELECT id, url, events, active, created_at
          FROM webhook_endpoints WHERE org_id = ${s.org.id} ORDER BY created_at DESC
      `,
    ]);
  const payload = {
    version: 1,
    generatedAt: new Date().toISOString(),
    scope: { type: "org", orgId: s.org.id },
    org: orgRows[0] ?? s.org,
    members,
    invites,
    environments,
    agents,
    actions,
    auditLog: auditRows,
    usage,
    webhooks: webhookRows,
    limits: {
      actions: 10000,
      actionsTruncated: actions.length >= 10000,
      auditTruncated: auditRows.length >= 10000,
    },
    notes: [
      "Broker receipts remain in the broker tenant and are included in evidence packs.",
      "Secrets, broker keys, webhook signing secrets, and session tokens are not exported.",
    ],
  };
  await audit({
    orgId: s.org.id,
    actorUserId: s.user.id,
    action: "org.exported",
    target: s.org.id,
    details: { actions: actions.length, auditEvents: auditRows.length },
  });
  c.header("content-disposition", `attachment; filename="tessera-export-${s.org.slug}.json"`);
  c.header("cache-control", "no-store");
  return c.json(payload);
});

routes.post("/v1/org/deletion-request", requireRole("owner"), async (c) => {
  const s = session(c);
  const body = z.object({ confirm: z.string() }).safeParse(await requestBody(c));
  if (!body.success || body.data.confirm !== s.org.name) {
    return fail(c, 400, "invalid_request", "Type the workspace name exactly to confirm");
  }
  const rows = await db()`
    UPDATE orgs
       SET deletion_requested_at = now(),
           deletion_scheduled_for = now() + interval '30 days'
     WHERE id = ${s.org.id}
    RETURNING deletion_scheduled_for
  `;
  const purgeAfter = String(rows[0]?.deletion_scheduled_for);
  await audit({
    orgId: s.org.id,
    actorUserId: s.user.id,
    action: "org.deletion_requested",
    target: s.org.id,
    details: { purgeAfter },
  });
  void sendEmail(
    deletionRequestEmail({
      to: s.user.email,
      orgName: s.org.name,
      purgeAfter,
    }),
  ).catch(() => undefined);
  return c.json({ deletionRequestedAt: new Date().toISOString(), purgeAfter });
});

routes.post("/v1/org/deletion-cancel", requireRole("owner"), async (c) => {
  const s = session(c);
  await db()`
    UPDATE orgs
       SET deletion_requested_at = NULL,
           deletion_scheduled_for = NULL
     WHERE id = ${s.org.id}
  `;
  await audit({
    orgId: s.org.id,
    actorUserId: s.user.id,
    action: "org.deletion_cancelled",
    target: s.org.id,
    details: {},
  });
  return c.json({ deletionRequestedAt: null, purgeAfter: null });
});

routes.patch("/v1/org/retention", requireRole("owner"), async (c) => {
  const s = session(c);
  const body = z.object({ retentionDays: z.number().int().min(30).max(3650) }).safeParse(await requestBody(c));
  if (!body.success) return fail(c, 400, "invalid_request", "retentionDays must be 30–3650");
  await db()`UPDATE orgs SET retention_days = ${body.data.retentionDays} WHERE id = ${s.org.id}`;
  await audit({
    orgId: s.org.id,
    actorUserId: s.user.id,
    action: "org.retention_updated",
    target: s.org.id,
    details: { retentionDays: body.data.retentionDays },
  });
  return c.json({ retentionDays: body.data.retentionDays });
});

routes.get("/v1/members", async (c) => {
  const s = session(c);
  const rows = await db()`
    SELECT u.id, u.email, u.name, m.role, m.created_at
      FROM memberships m JOIN users u ON u.id = m.user_id
     WHERE m.org_id = ${s.org.id} ORDER BY m.created_at
  `;
  return c.json({ items: rows });
});

routes.get("/v1/invites", async (c) => {
  const s = session(c);
  const rows = await db()`
    SELECT id, email, role, expires_at, accepted_at, created_at
      FROM invites WHERE org_id = ${s.org.id} ORDER BY created_at DESC
  `;
  return c.json({ items: rows });
});

routes.post("/v1/invites", requireRole("owner", "admin"), async (c) => {
  const s = session(c);
  const body = z
    .object({
      email: z.string().email(),
      role: z.enum(["admin", "member", "viewer"]).default("member"),
    })
    .safeParse(await requestBody(c));
  if (!body.success) return fail(c, 400, "invalid_request", "Valid email and role are required");
  const email = body.data.email.toLowerCase();
  const plan = planFor(s.org.plan);
  const seats = await db()`
    SELECT (
      (SELECT count(*) FROM memberships WHERE org_id = ${s.org.id}) +
      (SELECT count(*) FROM invites WHERE org_id = ${s.org.id} AND accepted_at IS NULL)
    )::int AS total
  `;
  if (Number(seats[0]?.total ?? 0) >= plan.members) {
    return fail(
      c,
      402,
      "plan_limit_exceeded",
      `The ${plan.name} plan includes ${plan.members} seats. Upgrade to invite more teammates.`,
    );
  }
  const existing = await db()`
    SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
     WHERE m.org_id = ${s.org.id} AND lower(u.email) = ${email}
  `;
  if (existing.length > 0) return fail(c, 409, "conflict", "That email is already a member");
  const token = randomToken(32);
  const id = uuid();
  const expiresAt = new Date(Date.now() + 7 * 86_400_000).toISOString();
  const inviteUrl = `${env.PUBLIC_BASE_URL.replace(/\/$/, "")}/invite/${token}`;
  await db()`
    INSERT INTO invites (id, org_id, email, role, token_hash, expires_at)
    VALUES (${id}, ${s.org.id}, ${email}, ${body.data.role}, ${sha256(token)}, ${expiresAt})
  `;
  await audit({
    orgId: s.org.id,
    actorUserId: s.user.id,
    action: "invite.created",
    target: id,
    details: { email, role: body.data.role },
  });
  const delivery = await sendEmail(
    inviteEmail({
      to: email,
      inviteUrl,
      orgName: s.org.name,
      inviterEmail: s.user.email,
      role: body.data.role,
    }),
  ).catch(() => ({ sent: false, provider: "resend" as const }));
  return c.json({
    id,
    email,
    role: body.data.role,
    expiresAt,
    inviteUrl,
    emailSent: delivery.sent,
    emailProvider: delivery.provider,
    notice: delivery.sent
      ? "Invite email sent. The invited user must sign in with this email."
      : "The invited user must sign in with this email; share the invite URL if needed.",
  });
});

routes.delete("/v1/invites/:id", requireRole("owner", "admin"), async (c) => {
  const s = session(c);
  const result = await db()`
    DELETE FROM invites WHERE id = ${c.req.param("id")} AND org_id = ${s.org.id}
  `;
  return c.json({ deleted: result.count > 0 });
});

// ── Environments ───────────────────────────────────────────────────────────

routes.get("/v1/environments", async (c) => {
  const s = session(c);
  const rows = await db()`
    SELECT e.id, e.name, e.slug, e.broker_tenant, e.created_at,
           (SELECT count(*)::int FROM agent_keys k WHERE k.environment_id = e.id AND k.revoked_at IS NULL) AS agent_keys
      FROM environments e WHERE e.org_id = ${s.org.id} ORDER BY e.created_at
  `;
  return c.json({ items: rows });
});

routes.post("/v1/environments", requireRole("owner", "admin"), async (c) => {
  const s = session(c);
  const body = z
    .object({
      name: z.string().min(1).max(64),
      slug: z.string().min(1).max(48).optional(),
    })
    .safeParse(await requestBody(c));
  if (!body.success) return fail(c, 400, "invalid_request", "Environment name is required");
  const plan = planFor(s.org.plan);
  if ((await environmentCount(s.org.id)) >= plan.environments) {
    return fail(
      c,
      402,
      "plan_limit_exceeded",
      `The ${plan.name} plan includes ${plan.environments} environments. Upgrade to add more.`,
    );
  }
  const slug = slugify(body.data.slug || body.data.name);
  const brokerTenant = `${s.org.slug}-${slug}`.slice(0, 120);
  const existing = await db()`
    SELECT 1 FROM environments WHERE org_id = ${s.org.id} AND slug = ${slug}
  `;
  if (existing.length > 0) return fail(c, 409, "conflict", "That environment already exists");
  let encryptedKey: string | null = null;
  let brokerKeyId: string | null = null;
  try {
    const brokerKey = await broker.createBrokerKey(brokerTenant, `${s.org.slug}/${slug}`);
    if (brokerKey.key) encryptedKey = encryptSecret(brokerKey.key);
    brokerKeyId = brokerKey.id;
  } catch (error) {
    if (!env.BROKER_DEMO_ALLOW) {
      return fail(
        c,
        502,
        "broker_error",
        error instanceof Error ? error.message : "Could not provision broker tenant",
      );
    }
  }
  const id = uuid();
  const rows = await db()`
    INSERT INTO environments (id, org_id, name, slug, broker_tenant, broker_key_enc, broker_key_id)
    VALUES (${id}, ${s.org.id}, ${body.data.name}, ${slug}, ${brokerTenant}, ${encryptedKey}, ${brokerKeyId})
    RETURNING id, name, slug, broker_tenant, created_at
  `;
  await audit({
    orgId: s.org.id,
    actorUserId: s.user.id,
    action: "environment.created",
    target: id,
    details: { name: body.data.name, slug },
  });
  void emitWebhook(s.org.id, "environment.created", {
    environmentId: id,
    name: body.data.name,
    slug,
  });
  return c.json(rows[0], 201);
});

routes.delete("/v1/environments/:id", requireRole("owner"), async (c) => {
  const s = session(c);
  const environment = await getEnvironment(s.org.id, c.req.param("id"));
  if (environment?.broker_key_id) {
    try {
      await broker.revokeBrokerKey(environment);
    } catch (error) {
      console.error("broker key revocation failed", error);
    }
  }
  const result = await db()`
    DELETE FROM environments WHERE id = ${c.req.param("id")} AND org_id = ${s.org.id}
  `;
  if (result.count > 0) {
    await audit({
      orgId: s.org.id,
      actorUserId: s.user.id,
      action: "environment.deleted",
      target: c.req.param("id"),
    });
  }
  return c.json({ deleted: result.count > 0 });
});

// ── Agent keys ─────────────────────────────────────────────────────────────

routes.get("/v1/agent-keys", async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return fail(c, 404, "not_found", "No environment yet");
  const rows = await db()`
    SELECT k.id, k.name, k.prefix, k.created_at, k.last_used_at, k.revoked_at,
           k.expires_at, k.delegation_mode, k.delegated_user_id,
           u.email AS delegated_email, u.name AS delegated_name
      FROM agent_keys k
      LEFT JOIN users u ON u.id = k.delegated_user_id
     WHERE k.environment_id = ${environment.id}
     ORDER BY k.created_at DESC
  `;
  return c.json({ items: rows });
});

routes.post("/v1/agent-keys", requireRole("owner", "admin", "member"), async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return fail(c, 404, "not_found", "Create an environment first");
  const body = z
    .object({
      name: z.string().min(1).max(64),
      expiresInDays: z.coerce.number().int().min(1).max(365).optional(),
      delegationMode: z.enum(["caller", "owner", "token"]).optional(),
    })
    .safeParse(await requestBody(c));
  if (!body.success) return fail(c, 400, "invalid_request", "Key name is required");
  const delegationMode =
    body.data.delegationMode ?? (authorityConfigured() ? "owner" : "caller");
  if (delegationMode !== "caller" && !authorityConfigured()) {
    return fail(
      c,
      503,
      "authority_not_configured",
      "Set TESSERA_AUTHORITY_HMAC_SECRET before creating delegated agent keys.",
    );
  }
  const generated = newAgentKey();
  const id = uuid();
  const expiresAt = body.data.expiresInDays
    ? new Date(Date.now() + body.data.expiresInDays * 86_400_000).toISOString()
    : null;
  await db()`
    INSERT INTO agent_keys
      (id, environment_id, name, prefix, key_hash, expires_at, delegation_mode, delegated_user_id)
    VALUES
      (${id}, ${environment.id}, ${body.data.name}, ${generated.prefix}, ${generated.hash},
       ${expiresAt}, ${delegationMode}, ${delegationMode === "caller" ? null : s.user.id})
  `;
  await audit({
    orgId: s.org.id,
    actorUserId: s.user.id,
    action: "agent_key.created",
    target: id,
    details: {
      name: body.data.name,
      environmentId: environment.id,
      delegationMode,
      delegatedTo: delegationMode === "caller" ? null : s.user.email,
    },
  });
  void emitWebhook(s.org.id, "agent_key.created", {
    agentKeyId: id,
    environmentId: environment.id,
    name: body.data.name,
    prefix: generated.prefix,
  });
  return c.json(
    {
      id,
      name: body.data.name,
      prefix: generated.prefix,
      key: generated.key,
      expiresAt,
      delegationMode,
      delegatedTo: delegationMode === "caller" ? null : s.user.email,
      notice: "Store this key now; it will not be shown again.",
    },
    201,
  );
});

routes.delete("/v1/agent-keys/:id", requireRole("owner", "admin"), async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return fail(c, 404, "not_found", "No environment yet");
  const result = await db()`
    UPDATE agent_keys SET revoked_at = now()
     WHERE id = ${c.req.param("id")} AND environment_id = ${environment.id} AND revoked_at IS NULL
  `;
  if (result.count > 0) {
    await audit({
      orgId: s.org.id,
      actorUserId: s.user.id,
      action: "agent_key.revoked",
      target: c.req.param("id"),
    });
    void emitWebhook(s.org.id, "agent_key.revoked", {
      agentKeyId: c.req.param("id"),
      environmentId: environment.id,
    });
  }
  return c.json({ revoked: result.count > 0 });
});

// ── Agent hot path (API-key auth) ───────────────────────────────────────────

routes.post("/v1/authority-tokens", requireRole("owner", "admin", "member"), async (c) => {
  const s = session(c);
  if (!authorityConfigured()) {
    return fail(
      c,
      503,
      "authority_not_configured",
      "Set TESSERA_AUTHORITY_HMAC_SECRET to issue delegation tokens.",
    );
  }
  const environment = await currentEnvironment(c, s);
  if (!environment) return fail(c, 404, "not_found", "Create an environment first");
  if (!allowAuthorityMint(`user:${s.user.id}`, env.TESSERA_AUTHORITY_MINT_PER_MINUTE)) {
    return fail(
      c,
      429,
      "rate_limited",
      "Too many authority tokens issued; retry in a minute.",
    );
  }
  const body = z
    .object({
      agentId: z.string().min(1).max(128),
      ttlSeconds: z.coerce.number().int().min(30).max(86_400).optional(),
    })
    .safeParse(await requestBody(c));
  if (!body.success) return fail(c, 400, "invalid_request", "agentId is required");
  const minted = mintAuthorityToken({
    userId: s.user.id,
    oidcSubject: s.user.oidc_subject,
    orgId: s.org.id,
    environmentId: environment.id,
    agentId: body.data.agentId,
    tenant: environment.broker_tenant,
    ttlSeconds: body.data.ttlSeconds,
  });
  await audit({
    orgId: s.org.id,
    actorUserId: s.user.id,
    action: "authority.token_issued",
    target: minted.claims.jti,
    details: {
      environmentId: environment.id,
      agentId: body.data.agentId,
      expiresAt: minted.expiresAt,
    },
  });
  return c.json({
    token: minted.token,
    tokenType: "Bearer",
    expiresAt: minted.expiresAt,
    claims: minted.claims,
    usage: "Pass this value as authorityToken on POST /v1/authorize.",
  });
});

const authorizeSchema = z
  .object({
    agentId: z.string().min(1).max(128),
    userId: z.string().min(1).max(256),
    tool: z.string().min(1).max(256),
    intent: z.string().min(1).max(8192),
    args: z.record(z.unknown()).default({}),
    toolSchemaHash: z.string().optional(),
    principal: z.record(z.unknown()).optional(),
    authorityToken: z.string().max(8192).optional(),
    agentMeta: z.record(z.unknown()).optional(),
    requestedScopes: z.array(z.string()).optional(),
    riskClass: z.string().optional(),
    declaredPurpose: z.string().optional(),
  })
  .passthrough();

const recordSchema = z
  .object({
    agentId: z.string().min(1),
    receiptId: z.string().min(1),
    resultHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
    status: z.string().optional(),
    errorClass: z.string().optional(),
    externalRef: z.string().optional(),
    completedAt: z.string().optional(),
  })
  .passthrough();

async function agentContext(c: any) {
  const raw =
    c.req.header("x-api-key") ||
    c.req.header("authorization")?.replace(/^Bearer\s+/i, "") ||
    "";
  if (!raw) return null;
  const rows = await db()`
    SELECT k.id, k.environment_id, k.scopes, k.expires_at, k.revoked_at,
           k.delegation_mode, k.delegated_user_id,
           u.email AS delegated_email, u.name AS delegated_name, u.oidc_subject,
           e.id AS env_id, e.org_id, e.name, e.slug, e.broker_tenant,
           e.broker_key_enc, e.broker_key_id
      FROM agent_keys k
      JOIN environments e ON e.id = k.environment_id
      LEFT JOIN users u ON u.id = k.delegated_user_id
     WHERE k.key_hash = ${sha256(raw)} LIMIT 1
  `;
  const row = rows[0];
  if (!row || row.revoked_at) return null;
  if (row.expires_at && new Date(row.expires_at as string) <= new Date()) return null;
  await db()`UPDATE agent_keys SET last_used_at = now() WHERE id = ${row.id as string}`;
  return {
    keyId: row.id as string,
    scopes: (row.scopes as Record<string, unknown>) ?? {},
    delegationMode: String(row.delegation_mode ?? "caller") as "caller" | "owner" | "token",
    delegatedUser: row.delegated_user_id
      ? {
          id: row.delegated_user_id as string,
          email: row.delegated_email as string,
          name: (row.delegated_name as string | null) ?? null,
          oidcSubject: (row.oidc_subject as string | null) ?? null,
        }
      : null,
    environment: {
      id: row.env_id as string,
      org_id: row.org_id as string,
      name: row.name as string,
      slug: row.slug as string,
      broker_tenant: row.broker_tenant as string,
      broker_key_enc: (row.broker_key_enc as string | null) ?? null,
      broker_key_id: (row.broker_key_id as string | null) ?? null,
    } as Environment & { broker_key_enc: string | null; broker_key_id: string | null },
  };
}

function agentAuthError(c: unknown) {
  return fail(c, 401, "unauthorized", "Invalid or missing agent API key");
}

routes.post("/v1/authorize", async (c) => {
  const auth = await agentContext(c);
  if (!auth) return agentAuthError(c);
  const parsed = authorizeSchema.safeParse(await requestBody(c));
  if (!parsed.success) return fail(c, 400, "invalid_request", "Invalid authorize payload");
  const organization = await db()`SELECT plan FROM orgs WHERE id = ${auth.environment.org_id}`;
  const plan = planFor(String(organization[0]?.plan ?? "team"));
  if ((await monthlyActionCount(auth.environment.org_id)) >= plan.actionsPerMonth) {
    return fail(
      c,
      402,
      "plan_limit_exceeded",
      `The ${plan.name} plan includes ${plan.actionsPerMonth.toLocaleString()} actions per month. Upgrade to continue.`,
    );
  }
  let authorizeBody: Record<string, unknown> = { ...parsed.data };
  try {
    if (auth.delegationMode === "owner") {
      if (parsed.data.authorityToken) {
        return fail(
          c,
          400,
          "invalid_request",
          "Owner-bound agent keys must not supply authorityToken.",
        );
      }
      if (!auth.delegatedUser) {
        return fail(c, 409, "conflict", "This agent key has no delegated user.");
      }
      if (!authorityConfigured()) {
        return fail(
          c,
          503,
          "authority_not_configured",
          "Set TESSERA_AUTHORITY_HMAC_SECRET to use owner-bound agent keys.",
        );
      }
      const minted = mintAuthorityToken({
        userId: auth.delegatedUser.id,
        oidcSubject: auth.delegatedUser.oidcSubject,
        orgId: auth.environment.org_id,
        environmentId: auth.environment.id,
        agentId: parsed.data.agentId,
        tenant: auth.environment.broker_tenant,
      });
      authorizeBody = {
        ...authorizeBody,
        userId: auth.delegatedUser.id,
        authorityToken: minted.token,
      };
      delete authorizeBody.principal;
    } else if (auth.delegationMode === "token") {
      if (!parsed.data.authorityToken) {
        return fail(c, 400, "invalid_request", "This agent key requires authorityToken.");
      }
      verifyAuthorityToken(parsed.data.authorityToken, {
        tenant: auth.environment.broker_tenant,
        orgId: auth.environment.org_id,
        environmentId: auth.environment.id,
        agentId: parsed.data.agentId,
      });
    }
  } catch (error) {
    return fail(
      c,
      401,
      "invalid_authority",
      error instanceof Error ? error.message : "Invalid authority token",
    );
  }
  const idempotencyKey = c.req.header("idempotency-key");
  try {
    const response = await broker.authorize(auth.environment, authorizeBody, idempotencyKey);
    await persistAction(auth.environment, response);
    return c.json(response);
  } catch (error) {
    if (error instanceof broker.BrokerError) {
      return c.json(error.body ?? { error: { code: "broker_error", message: error.message } }, error.status as 400);
    }
    throw error;
  }
});

routes.post("/v1/record", async (c) => {
  const auth = await agentContext(c);
  if (!auth) return agentAuthError(c);
  const parsed = recordSchema.safeParse(await requestBody(c));
  if (!parsed.success) return fail(c, 400, "invalid_request", "Invalid record payload");
  const idempotencyKey = c.req.header("idempotency-key");
  try {
    const response = await broker.record(auth.environment, parsed.data, idempotencyKey);
    await persistOutcome(auth.environment, parsed.data.receiptId, response);
    return c.json(response);
  } catch (error) {
    if (error instanceof broker.BrokerError) {
      return c.json(error.body ?? { error: { code: "broker_error", message: error.message } }, error.status as 400);
    }
    throw error;
  }
});

routes.post("/v1/proxy", async (c) => {
  const auth = await agentContext(c);
  if (!auth) return agentAuthError(c);
  try {
    const response = (await broker.proxy(
      auth.environment,
      await requestBody(c),
      c.req.header("idempotency-key"),
    )) as {
      outcomeRecorded?: boolean;
      authorizationReceiptId?: string;
      outcomeReceiptId?: string;
      outcomeReceipt?: Record<string, unknown>;
    } & Record<string, unknown>;
    if (
      response.outcomeRecorded &&
      response.authorizationReceiptId &&
      response.outcomeReceipt
    ) {
      await persistOutcome(auth.environment, response.authorizationReceiptId, {
        status: "recorded",
        receiptId: response.outcomeReceiptId ?? "",
        receipt: response.outcomeReceipt,
      });
    }
    return c.json(response);
  } catch (error) {
    if (error instanceof broker.BrokerError) {
      return c.json(error.body ?? { error: { code: "broker_error", message: error.message } }, error.status as 400);
    }
    throw error;
  }
});

// ── Actions, agents, usage, audit ──────────────────────────────────────────

routes.get("/v1/actions", async (c) => {
  const s = session(c);
  const limit = Math.min(Math.max(Number(c.req.query("limit") ?? 50), 1), 100);
  const environmentId = c.req.query("environmentId");
  const agentId = c.req.query("agentId");
  const tool = c.req.query("tool");
  const decision = c.req.query("decision");
  const outcome = c.req.query("outcome");
  const cursor = c.req.query("cursor");
  let since: string | null = null;
  let until: string | null = null;
  try {
    if (c.req.query("since")) since = parseDateParam(c.req.query("since"), new Date()).toISOString();
    if (c.req.query("until")) until = parseDateParam(c.req.query("until"), new Date(), true).toISOString();
  } catch (error) {
    return fail(c, 400, "invalid_request", error instanceof Error ? error.message : "Invalid date range");
  }
  let query = db()`
    SELECT action_id, environment_id, agent_id, principal_id, tool, decision,
           outcome_status, policy_id, policy_version, policy_hash, credential_issuer,
           credential_thumbprint, receipt_id, created_at, completed_at, verified
      FROM actions WHERE org_id = ${s.org.id}
  `;
  if (environmentId) query = db()`${query} AND environment_id = ${environmentId}`;
  if (agentId) query = db()`${query} AND agent_id = ${agentId}`;
  if (tool) query = db()`${query} AND tool = ${tool}`;
  if (decision) query = db()`${query} AND decision = ${decision}`;
  if (outcome) query = db()`${query} AND outcome_status = ${outcome}`;
  if (since) query = db()`${query} AND created_at >= ${since}`;
  if (until) query = db()`${query} AND created_at <= ${until}`;
  if (cursor) {
    try {
      const [createdAt, actionId] = Buffer.from(cursor, "base64url").toString("utf8").split("|");
      if (!createdAt || !actionId) return fail(c, 400, "invalid_cursor", "Invalid cursor");
      query = db()`${query} AND (created_at, action_id) < (${createdAt}::timestamptz, ${actionId})`;
    } catch {
      return fail(c, 400, "invalid_cursor", "Invalid cursor");
    }
  }
  const rows = await db()`${query} ORDER BY created_at DESC, action_id DESC LIMIT ${limit + 1}`;
  const items = rows.slice(0, limit);
  const last = items[items.length - 1];
  const nextCursor =
    rows.length > limit && last
      ? Buffer.from(`${new Date(last.created_at as string).toISOString()}|${last.action_id}`).toString("base64url")
      : null;
  return c.json({ items: items.map(actionSummary), nextCursor });
});

routes.get("/v1/actions/:actionId", async (c) => {
  const s = session(c);
  const rows = await db()`
    SELECT * FROM actions WHERE action_id = ${c.req.param("actionId")} AND org_id = ${s.org.id}
  `;
  const action = rows[0];
  if (!action) return fail(c, 404, "not_found", "Action not found");
  const reviewRows = await db()`
    SELECT id, status, reason, resolution_note, created_at, resolved_at
      FROM action_reviews WHERE action_id = ${action.action_id as string} LIMIT 1
  `;
  let verification: Awaited<ReturnType<typeof broker.verifyRecord>> | null = null;
  const payload = action.payload as { authorization?: any; outcome?: any };
  if (payload.authorization) {
    try {
      verification = await broker.verifyRecord(payload.authorization, payload.outcome ?? null);
      if (verification.valid) {
        await db()`
          UPDATE actions
             SET verified = true,
                 verified_at = COALESCE(verified_at, now())
           WHERE action_id = ${action.action_id as string}
        `;
      }
    } catch {
      verification = { valid: false, errors: ["verification service unavailable"] };
    }
  }
  return c.json({
    ...actionSummary(action),
    verified: verification?.valid ?? action.verified,
    payload: action.payload,
    review: reviewRows[0] ?? null,
    verification,
  });
});

routes.get("/v1/actions/:actionId/agent-receipt", async (c) => {
  const s = session(c);
  const rows = await db()`
    SELECT environment_id, payload FROM actions
     WHERE action_id = ${c.req.param("actionId")} AND org_id = ${s.org.id}
  `;
  const action = rows[0];
  if (!action) return fail(c, 404, "not_found", "Action not found");
  if (!env.AGENT_RECEIPT_ED25519_KEY) {
    return fail(c, 503, "not_configured", "Agent Receipts export is not configured");
  }
  const environment = await getEnvironment(s.org.id, action.environment_id as string);
  if (!environment) return fail(c, 404, "not_found", "Environment not found");
  const payload = action.payload as { authorization?: ReceiptV2; outcome?: ReceiptV2 | null };
  if (!payload.authorization) return fail(c, 404, "not_found", "Authorization record is missing");
  const issuanceDate = new Date().toISOString();
  let credential = buildAgentReceipt({
    authorization: payload.authorization,
    outcome: payload.outcome ?? null,
    tenant: environment.broker_tenant,
    issuerDid:
      env.AGENT_RECEIPT_ISSUER_DID ??
      `did:web:${new URL(env.PUBLIC_BASE_URL).host}`,
    issuanceDate,
  });
  if (env.AGENT_RECEIPT_TSA_URL) {
    const trustedTimestamp = await requestTrustedTimestamp(
      env.AGENT_RECEIPT_TSA_URL,
      canonicalAgentReceipt(credential),
    );
    credential = buildAgentReceipt({
      authorization: payload.authorization,
      outcome: payload.outcome ?? null,
      tenant: environment.broker_tenant,
      issuerDid:
        env.AGENT_RECEIPT_ISSUER_DID ??
        `did:web:${new URL(env.PUBLIC_BASE_URL).host}`,
      issuanceDate,
      trustedTimestamp,
    });
  }
  credential = signAgentReceipt(credential, env.AGENT_RECEIPT_ED25519_KEY);
  return c.body(JSON.stringify(credential), 200, {
    "content-type": "application/ld+json",
    "content-disposition": `attachment; filename="agent-receipt-${c.req.param("actionId")}.json"`,
  });
});

routes.get("/v1/agents", async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return c.json({ items: [] });
  const rows = await db()`
    SELECT agent_id,
           count(*)::int AS actions,
           max(created_at) AS last_seen,
           sum(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END)::int AS denied,
           sum(CASE WHEN outcome_status = 'success' THEN 1 ELSE 0 END)::int AS succeeded
      FROM actions
     WHERE org_id = ${s.org.id} AND environment_id = ${environment.id}
     GROUP BY agent_id ORDER BY last_seen DESC LIMIT 200
  `;
  return c.json({ items: rows });
});

routes.get("/v1/usage", async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) {
    const plan = planFor(s.org.plan);
    return c.json({ items: [], plan: plan.name, limit: plan.actionsPerMonth, used: 0, remaining: plan.actionsPerMonth });
  }
  const rows = await db()`
    SELECT day, actions, allowed, denied
      FROM usage_daily
     WHERE org_id = ${s.org.id} AND environment_id = ${environment.id}
     ORDER BY day DESC LIMIT 31
  `;
  const total = rows.reduce((sum, row) => sum + Number(row.actions), 0);
  const plan = planFor(s.org.plan);
  const limit = plan.actionsPerMonth;
  return c.json({
    plan: plan.name,
    limit,
    used: total,
    remaining: Math.max(0, limit - total),
    items: rows,
  });
});

routes.get("/v1/audit", async (c) => {
  const s = session(c);
  const rows = await db()`
    SELECT id, actor_user_id, actor_type, action, target, details, created_at
      FROM audit_log WHERE org_id = ${s.org.id}
     ORDER BY created_at DESC LIMIT 100
  `;
  return c.json({ items: rows });
});

// ── Analytics and notifications ────────────────────────────────────────────

routes.get("/v1/analytics", async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return fail(c, 404, "not_found", "Create an environment first");
  try {
    return c.json(
      await buildAnalytics({
        orgId: s.org.id,
        environment,
        range: c.req.query("range"),
        since: c.req.query("since"),
        until: c.req.query("until"),
        agentId: c.req.query("agentId"),
      }),
    );
  } catch (error) {
    return fail(c, 400, "invalid_request", error instanceof Error ? error.message : "Invalid analytics scope");
  }
});

routes.get("/v1/notifications", async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return c.json({ items: [] });
  return c.json({ items: await buildNotifications(s.org.id, environment) });
});

routes.get("/v1/search", async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return c.json({ actions: [], agents: [], policies: [], verificationLinks: [] });
  return c.json(await searchResources(s.org.id, environment, c.req.query("q") ?? ""));
});

// ── Integrations ───────────────────────────────────────────────────────────

function integrationFailure(c: any, error: unknown) {
  if (error instanceof IntegrationError) {
    return fail(c, error.status, error.code, error.message);
  }
  throw error;
}

routes.get("/v1/integrations", async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return c.json({ items: [], providers: PROVIDERS });
  return c.json({
    items: await listIntegrations(s.org.id, environment.id),
    providers: PROVIDERS,
  });
});

routes.post("/v1/integrations", requireRole("owner", "admin", "member"), async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return fail(c, 404, "not_found", "Create an environment first");
  const body = z
    .object({
      provider: z.string().min(1).max(64),
      name: z.string().trim().min(1).max(80).optional(),
      scopes: z.array(z.string().min(1).max(64)).min(1).max(20).optional(),
      credential: z.record(z.string()).optional(),
    })
    .safeParse(await requestBody(c));
  if (!body.success) return fail(c, 400, "invalid_request", "Invalid integration request");
  try {
    const result = await createIntegration({
      orgId: s.org.id,
      environment,
      user: { id: s.user.id, email: s.user.email },
      providerId: body.data.provider,
      name: body.data.name,
      scopes: body.data.scopes,
      credential: body.data.credential,
    });
    return c.json(result, 201);
  } catch (error) {
    return integrationFailure(c, error);
  }
});

routes.post("/v1/integrations/:id/test", requireRole("owner", "admin", "member"), async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return fail(c, 404, "not_found", "Create an environment first");
  try {
    return c.json(
      await testIntegration({
        orgId: s.org.id,
        environment,
        user: { id: s.user.id },
        id: c.req.param("id"),
      }),
    );
  } catch (error) {
    return integrationFailure(c, error);
  }
});

routes.post("/v1/integrations/:id/rotate", requireRole("owner", "admin"), async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return fail(c, 404, "not_found", "Create an environment first");
  const body = z
    .object({ credential: z.record(z.string()).optional() })
    .safeParse(await requestBody(c));
  if (!body.success) return fail(c, 400, "invalid_request", "Invalid credential payload");
  try {
    return c.json(
      await rotateIntegration({
        orgId: s.org.id,
        environment,
        user: { id: s.user.id },
        id: c.req.param("id"),
        credential: body.data.credential,
      }),
    );
  } catch (error) {
    return integrationFailure(c, error);
  }
});

// ── Policies ───────────────────────────────────────────────────────────────

routes.get("/v1/policies", async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return c.json({ items: [] });
  try {
    return c.json(await broker.listPolicies(environment));
  } catch (error) {
    if (error instanceof broker.BrokerError) {
      return c.json(error.body ?? { error: { code: "broker_error", message: error.message } }, error.status as 400);
    }
    throw error;
  }
});

routes.get("/v1/policies/propose", async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return fail(c, 404, "not_found", "Create an environment first");
  try {
    return c.json(await broker.proposePolicy(environment));
  } catch (error) {
    if (error instanceof broker.BrokerError) {
      return c.json(error.body ?? { error: { code: "broker_error", message: error.message } }, error.status as 400);
    }
    throw error;
  }
});

routes.get("/v1/policies/:id", async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return fail(c, 404, "not_found", "Create an environment first");
  try {
    return c.json(await broker.getPolicy(environment, c.req.param("id")));
  } catch (error) {
    if (error instanceof broker.BrokerError) {
      return c.json(error.body ?? { error: { code: "broker_error", message: error.message } }, error.status as 400);
    }
    throw error;
  }
});

routes.put("/v1/policies/:id", requireRole("owner", "admin"), async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return fail(c, 404, "not_found", "Create an environment first");
  try {
    const result = await broker.putPolicy(environment, c.req.param("id"), await requestBody(c));
    await audit({
      orgId: s.org.id,
      actorUserId: s.user.id,
      action: "policy.upserted",
      target: c.req.param("id"),
      details: { environmentId: environment.id },
    });
    void emitWebhook(s.org.id, "policy.upserted", {
      policyId: c.req.param("id"),
      environmentId: environment.id,
    });
    return c.json(result);
  } catch (error) {
    if (error instanceof broker.BrokerError) {
      return c.json(error.body ?? { error: { code: "broker_error", message: error.message } }, error.status as 400);
    }
    throw error;
  }
});

routes.delete("/v1/policies/:id", requireRole("owner", "admin"), async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return fail(c, 404, "not_found", "Create an environment first");
  try {
    const result = await broker.deletePolicy(environment, c.req.param("id"));
    await audit({
      orgId: s.org.id,
      actorUserId: s.user.id,
      action: "policy.deleted",
      target: c.req.param("id"),
      details: { environmentId: environment.id },
    });
    return c.json(result);
  } catch (error) {
    if (error instanceof broker.BrokerError) {
      return c.json(error.body ?? { error: { code: "broker_error", message: error.message } }, error.status as 400);
    }
    throw error;
  }
});

// ── Reviews ────────────────────────────────────────────────────────────────

routes.post("/v1/actions/:actionId/review", requireRole("owner", "admin", "member"), async (c) => {
  const s = session(c);
  const body = z
    .object({ reason: z.string().max(512).optional() })
    .safeParse(await requestBody(c));
  if (!body.success) return fail(c, 400, "invalid_request", "Invalid review request");
  const rows = await db()`
    SELECT action_id, environment_id, agent_id, tool, decision, outcome_status
      FROM actions WHERE action_id = ${c.req.param("actionId")} AND org_id = ${s.org.id}
  `;
  const action = rows[0];
  if (!action) return fail(c, 404, "not_found", "Action not found");
  const id = uuid();
  try {
    await db()`
      INSERT INTO action_reviews (id, org_id, environment_id, action_id, reason, requested_by)
      VALUES (${id}, ${s.org.id}, ${action.environment_id as string}, ${action.action_id as string}, ${body.data.reason ?? null}, ${s.user.id})
    `;
  } catch (error) {
    if (typeof error === "object" && error && "code" in error && error.code === "23505") {
      return fail(c, 409, "conflict", "This action is already in the review queue");
    }
    throw error;
  }
  await audit({
    orgId: s.org.id,
    actorUserId: s.user.id,
    action: "action.review_requested",
    target: action.action_id as string,
    details: { reason: body.data.reason ?? null },
  });
  return c.json({ id, actionId: action.action_id, status: "pending" }, 201);
});

routes.get("/v1/reviews", async (c) => {
  const s = session(c);
  const status = c.req.query("status") ?? "pending";
  if (!["pending", "approved", "rejected", "all"].includes(status)) {
    return fail(c, 400, "invalid_request", "Invalid review status");
  }
  const rows = await db()`
    SELECT r.id, r.action_id, r.status, r.reason, r.resolution_note, r.created_at, r.resolved_at,
           a.agent_id, a.principal_id, a.tool, a.decision, a.outcome_status, a.created_at AS action_created_at
      FROM action_reviews r JOIN actions a ON a.action_id = r.action_id
     WHERE r.org_id = ${s.org.id}
       AND (${status} = 'all' OR r.status = ${status})
     ORDER BY r.created_at DESC LIMIT 100
  `;
  return c.json({ items: rows });
});

routes.post("/v1/reviews/:id/decision", requireRole("owner", "admin"), async (c) => {
  const s = session(c);
  const body = z
    .object({
      decision: z.enum(["approve", "reject"]),
      note: z.string().max(512).optional(),
    })
    .safeParse(await requestBody(c));
  if (!body.success) return fail(c, 400, "invalid_request", "decision must be approve or reject");
  const rows = await db()`
    UPDATE action_reviews
       SET status = ${body.data.decision === "approve" ? "approved" : "rejected"},
           resolution_note = ${body.data.note ?? null},
           resolved_by = ${s.user.id},
           resolved_at = now()
     WHERE id = ${c.req.param("id")} AND org_id = ${s.org.id} AND status = 'pending'
    RETURNING id, action_id, status, resolved_at
  `;
  if (!rows[0]) return fail(c, 404, "not_found", "Pending review not found");
  await audit({
    orgId: s.org.id,
    actorUserId: s.user.id,
    action: `action.review_${body.data.decision === "approve" ? "approved" : "rejected"}`,
    target: rows[0].action_id as string,
    details: { reviewId: rows[0].id, note: body.data.note ?? null },
  });
  return c.json(rows[0]);
});

// ── Authority transitions ──────────────────────────────────────────────────

routes.get("/v1/transitions", async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return c.json({ items: [], verified: true });
  try {
    const result = await broker.keyEvents(environment);
    const items = Array.isArray(result.items)
      ? result.items.filter(
          (event: any) => event?.details?.transitionType,
        )
      : [];
    return c.json({ ...result, items });
  } catch (error) {
    if (error instanceof broker.BrokerError) {
      return c.json(
        error.body ?? { error: { code: "broker_error", message: error.message } },
        error.status as 400,
      );
    }
    throw error;
  }
});

routes.post("/v1/transitions", requireRole("owner", "admin"), async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return fail(c, 404, "not_found", "Create an environment first");
  const body = z
    .object({
      type: z.enum([
        "authority.stepped_up",
        "authority.narrowed",
        "authority.granted",
        "authority.delegated",
        "authority.changed",
      ]),
      target: z.string().min(1).max(256),
      reason: z.string().max(512).optional(),
      details: z.record(z.unknown()).optional(),
    })
    .safeParse(await requestBody(c));
  if (!body.success) return fail(c, 400, "invalid_request", "Invalid transition");
  try {
    const event = await broker.appendTransition(environment, body.data);
    await audit({
      orgId: s.org.id,
      actorUserId: s.user.id,
      action: body.data.type,
      target: body.data.target,
      details: { environmentId: environment.id, reason: body.data.reason ?? null },
    });
    return c.json(event, 201);
  } catch (error) {
    if (error instanceof broker.BrokerError) {
      return c.json(
        error.body ?? { error: { code: "broker_error", message: error.message } },
        error.status as 400,
      );
    }
    throw error;
  }
});

// ── Evidence packs ─────────────────────────────────────────────────────────

routes.get("/v1/evidence/readiness", async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return fail(c, 404, "not_found", "Create an environment first");
  const frameworks = c.req.query("frameworks")?.split(",").filter(Boolean);
  try {
    const filters = normalizeEvidenceFilters({
      frameworks,
      since: c.req.query("since"),
      until: c.req.query("until"),
      agentId: c.req.query("agentId"),
    });
    return c.json(await buildEvidenceSummary(s.org.name, environment, filters));
  } catch (error) {
    return fail(c, 400, "invalid_request", error instanceof Error ? error.message : "Invalid evidence scope");
  }
});

routes.get("/v1/evidence-packs", async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return c.json({ items: [] });
  const rows = await db()`
    SELECT id, environment_id, status, filters, summary, created_at, expires_at, share_expires_at
      FROM evidence_packs
     WHERE org_id = ${s.org.id} AND environment_id = ${environment.id}
     ORDER BY created_at DESC LIMIT 50
  `;
  return c.json({
    items: rows.map((row) => ({
      ...row,
      hasShare: Boolean(
        row.share_expires_at && new Date(row.share_expires_at as string) > new Date(),
      ),
      downloadUrl: `/v1/evidence-packs/${row.id}/download`,
      reportUrl: `/v1/evidence-packs/${row.id}/report`,
    })),
  });
});

routes.post("/v1/evidence-packs", requireRole("owner", "admin", "member"), async (c) => {
  const s = session(c);
  const environment = await currentEnvironment(c, s);
  if (!environment) return fail(c, 404, "not_found", "Create an environment first");
  const id = uuid();
  let filters;
  let summary: EvidencePackSummary;
  try {
    filters = normalizeEvidenceFilters(await requestBody(c));
    if (filters.agentId) {
      return fail(c, 400, "invalid_request", "Agent-scoped packs are not supported; the signed archive is environment-wide");
    }
    summary = await buildEvidenceSummary(s.org.name, environment, filters, { plannedPack: true });
  } catch (error) {
    return fail(c, 400, "invalid_request", error instanceof Error ? error.message : "Invalid evidence scope");
  }
  try {
    const archive = await broker.exportTenantArchive(environment);
    const objectKey = await evidenceStorage().put(`${id}.tar.gz`, archive);
    await db()`
      INSERT INTO evidence_packs (id, org_id, environment_id, status, object_key, filters, summary, created_by)
      VALUES (${id}, ${s.org.id}, ${environment.id}, 'ready', ${objectKey}, ${db().json(filters as never)}, ${db().json(summary as never)}, ${s.user.id})
    `;
    await audit({
      orgId: s.org.id,
      actorUserId: s.user.id,
      action: "evidence_pack.created",
      target: id,
      details: {
        environmentId: environment.id,
        bytes: archive.byteLength,
        frameworks: filters.frameworks,
        since: filters.since,
        until: filters.until,
      },
    });
    void emitWebhook(s.org.id, "evidence_pack.created", {
      evidencePackId: id,
      environmentId: environment.id,
      bytes: archive.byteLength,
    });
    return c.json(
      {
        id,
        status: "ready",
        bytes: archive.byteLength,
        summary,
        downloadUrl: `/v1/evidence-packs/${id}/download`,
        reportUrl: `/v1/evidence-packs/${id}/report`,
      },
      201,
    );
  } catch (error) {
    await db()`
      INSERT INTO evidence_packs (id, org_id, environment_id, status, filters, summary, created_by)
      VALUES (${id}, ${s.org.id}, ${environment.id}, 'failed', ${db().json(filters as never)}, ${db().json(summary as never)}, ${s.user.id})
    `;
    return fail(
      c,
      502,
      "broker_error",
      error instanceof Error ? error.message : "Could not export evidence",
    );
  }
});

routes.get("/v1/evidence-packs/:id", async (c) => {
  const s = session(c);
  const rows = await db()`
    SELECT id, environment_id, status, filters, summary, created_at, expires_at, share_expires_at
      FROM evidence_packs
     WHERE id = ${c.req.param("id")} AND org_id = ${s.org.id}
  `;
  const pack = rows[0];
  if (!pack) return fail(c, 404, "not_found", "Evidence pack not found");
  return c.json({
    ...pack,
    hasShare: Boolean(
      pack.share_expires_at && new Date(pack.share_expires_at as string) > new Date(),
    ),
    downloadUrl: `/v1/evidence-packs/${pack.id}/download`,
    reportUrl: `/v1/evidence-packs/${pack.id}/report`,
  });
});

routes.get("/v1/evidence-packs/:id/report", async (c) => {
  const s = session(c);
  const rows = await db()`
    SELECT id, summary, created_at, expires_at, status
      FROM evidence_packs
     WHERE id = ${c.req.param("id")} AND org_id = ${s.org.id}
  `;
  const pack = rows[0];
  if (!pack || pack.status !== "ready") return fail(c, 404, "not_found", "Evidence pack not found");
  const summary = pack.summary as EvidencePackSummary;
  if (!summary || summary.version !== 1) {
    return fail(c, 409, "rebuild_required", "This pack predates reviewer reports; rebuild it");
  }
  const html = renderEvidenceReport(summary, {
    id: String(pack.id),
    createdAt: String(pack.created_at),
    expiresAt: pack.expires_at ? String(pack.expires_at) : null,
  });
  return new Response(html, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "content-disposition": `attachment; filename="tessera-evidence-${pack.id}.html"`,
      "cache-control": "no-store",
    },
  });
});

routes.post("/v1/evidence-packs/:id/share", requireRole("owner", "admin", "member"), async (c) => {
  const s = session(c);
  const body = z
    .object({ expiresInDays: z.number().int().min(1).max(90).optional() })
    .safeParse(await requestBody(c));
  if (!body.success) return fail(c, 400, "invalid_request", "expiresInDays must be between 1 and 90");
  const rows = await db()`
    SELECT id, status FROM evidence_packs WHERE id = ${c.req.param("id")} AND org_id = ${s.org.id}
  `;
  const pack = rows[0];
  if (!pack || pack.status !== "ready") return fail(c, 404, "not_found", "Evidence pack not found");
  const token = randomToken(32);
  const expiresAt = new Date(Date.now() + (body.data.expiresInDays ?? 30) * 86_400_000);
  await db()`
    UPDATE evidence_packs
       SET share_token_hash = ${sha256(token)}, share_expires_at = ${expiresAt.toISOString()}
     WHERE id = ${c.req.param("id")} AND org_id = ${s.org.id}
  `;
  await audit({
    orgId: s.org.id,
    actorUserId: s.user.id,
    action: "evidence_pack.shared",
    target: c.req.param("id"),
    details: { expiresAt: expiresAt.toISOString() },
  });
  return c.json({
    url: `${env.PUBLIC_BASE_URL.replace(/\/$/, "")}/evidence/share/${token}`,
    expiresAt: expiresAt.toISOString(),
  });
});

routes.delete("/v1/evidence-packs/:id/share", requireRole("owner", "admin", "member"), async (c) => {
  const s = session(c);
  const result = await db()`
    UPDATE evidence_packs
       SET share_token_hash = NULL, share_expires_at = NULL
     WHERE id = ${c.req.param("id")} AND org_id = ${s.org.id}
  `;
  await audit({
    orgId: s.org.id,
    actorUserId: s.user.id,
    action: "evidence_pack.share_revoked",
    target: c.req.param("id"),
    details: {},
  });
  return c.json({ revoked: result.count > 0 });
});

routes.get("/v1/evidence-packs/:id/download", async (c) => {
  const s = session(c);
  const rows = await db()`
    SELECT object_key, status FROM evidence_packs
     WHERE id = ${c.req.param("id")} AND org_id = ${s.org.id}
  `;
  const pack = rows[0];
  if (!pack || pack.status !== "ready" || !pack.object_key) {
    return fail(c, 404, "not_found", "Evidence pack not found");
  }
  let file: Uint8Array;
  try {
    file = await evidenceStorage().get(pack.object_key as string);
  } catch {
    return fail(c, 404, "not_found", "Evidence pack not found");
  }
  return new Response(file, {
    status: 200,
    headers: {
      "content-type": "application/gzip",
      "content-disposition": `attachment; filename="tessera-evidence-${c.req.param("id")}.tar.gz"`,
      "cache-control": "no-store",
    },
  });
});

// ── Billing ────────────────────────────────────────────────────────────────

routes.get("/v1/billing", async (c) => {
  const s = session(c);
  return c.json(await getBillingState(s.org.id));
});

routes.post("/v1/billing/checkout", requireRole("owner", "admin"), async (c) => {
  const s = session(c);
  const body = z
    .object({ plan: z.enum(["team", "growth"]) })
    .safeParse(await requestBody(c));
  if (!body.success) return fail(c, 400, "invalid_request", "plan must be team or growth");
  const client = getStripe();
  const price = priceForPlan(body.data.plan);
  if (!client || !price) {
    return fail(c, 503, "not_configured", "Stripe billing is not configured");
  }
  const billing = await getBillingState(s.org.id);
  let customerId = billing.customerId;
  if (!customerId) {
    const customer = await client.customers.create({
      email: s.user.email,
      name: s.org.name,
      metadata: { orgId: s.org.id },
    });
    customerId = customer.id;
    await setStripeCustomer(s.org.id, customerId);
  }
  if (!customerId) return fail(c, 500, "internal_error", "Could not create billing customer");
  const base = env.PUBLIC_BASE_URL.replace(/\/$/, "");
  const checkoutSession = await client.checkout.sessions.create({
    mode: "subscription",
    customer: customerId,
    line_items: [{ price, quantity: 1 }],
    success_url: `${base}/settings?billing=success`,
    cancel_url: `${base}/settings?billing=cancelled`,
    client_reference_id: s.org.id,
    metadata: { orgId: s.org.id, plan: body.data.plan },
    subscription_data: { metadata: { orgId: s.org.id, plan: body.data.plan } },
    allow_promotion_codes: true,
  });
  return c.json({ url: checkoutSession.url });
});

routes.post("/v1/billing/portal", requireRole("owner", "admin"), async (c) => {
  const s = session(c);
  const client = getStripe();
  if (!client) return fail(c, 503, "not_configured", "Stripe billing is not configured");
  const billing = await getBillingState(s.org.id);
  if (!billing.customerId) return fail(c, 404, "not_found", "No billing customer yet");
  const portalSession = await client.billingPortal.sessions.create({
    customer: billing.customerId,
    return_url: env.STRIPE_PORTAL_RETURN_URL ?? `${env.PUBLIC_BASE_URL.replace(/\/$/, "")}/settings`,
  });
  return c.json({ url: portalSession.url });
});

// ── Webhooks ───────────────────────────────────────────────────────────────

routes.get("/v1/webhooks", async (c) => {
  const s = session(c);
  const rows = await db()`
    SELECT id, url, events, active, created_at
      FROM webhook_endpoints WHERE org_id = ${s.org.id}
     ORDER BY created_at DESC
  `;
  return c.json({ items: rows });
});

routes.post("/v1/webhooks", requireRole("owner", "admin"), async (c) => {
  const s = session(c);
  const body = z
    .object({
      url: z.string().url(),
      events: z.array(z.string()).default([]),
    })
    .safeParse(await requestBody(c));
  if (!body.success) return fail(c, 400, "invalid_request", "A valid webhook URL is required");
  try {
    const created = await createWebhookEndpoint({
      orgId: s.org.id,
      url: body.data.url,
      events: body.data.events,
    });
    await audit({
      orgId: s.org.id,
      actorUserId: s.user.id,
      action: "webhook.created",
      target: created.id,
      details: { url: body.data.url, events: body.data.events },
    });
    return c.json(
      {
        id: created.id,
        url: body.data.url,
        events: body.data.events.length ? body.data.events : ["*"],
        secret: created.secret,
        notice: "Store this signing secret now; it will not be shown again.",
      },
      201,
    );
  } catch (error) {
    return fail(c, 400, "invalid_request", error instanceof Error ? error.message : String(error));
  }
});

routes.delete("/v1/webhooks/:id", requireRole("owner", "admin"), async (c) => {
  const s = session(c);
  const result = await db()`
    DELETE FROM webhook_endpoints WHERE id = ${c.req.param("id")} AND org_id = ${s.org.id}
  `;
  return c.json({ deleted: result.count > 0 });
});

routes.get("/v1/webhook-deliveries", async (c) => {
  const s = session(c);
  const rows = await db()`
    SELECT id, endpoint_id, event, status, attempts, last_error, created_at, delivered_at
      FROM webhook_deliveries WHERE org_id = ${s.org.id}
     ORDER BY created_at DESC LIMIT 100
  `;
  return c.json({ items: rows });
});

routes.get("/v1/webhook-events", (c) => c.json({ events: WEBHOOK_EVENTS }));

// ── Verification links ─────────────────────────────────────────────────────

routes.get("/v1/verification-links", async (c) => {
  const s = session(c);
  const rows = await db()`
    SELECT vl.id, vl.action_id, vl.expires_at, vl.created_at, vl.view_count, vl.revoked_at
      FROM verification_links vl
     WHERE vl.org_id = ${s.org.id}
     ORDER BY vl.created_at DESC LIMIT 100
  `;
  return c.json({ items: rows });
});

routes.post("/v1/verification-links", requireRole("owner", "admin", "member"), async (c) => {
  const s = session(c);
  const body = z
    .object({
      actionId: z.string().min(1),
      expiresInDays: z.coerce.number().int().min(1).max(365).default(30),
    })
    .safeParse(await requestBody(c));
  if (!body.success) return fail(c, 400, "invalid_request", "actionId is required");
  const action = await db()`
    SELECT action_id, environment_id FROM actions
     WHERE action_id = ${body.data.actionId} AND org_id = ${s.org.id}
  `;
  if (!action[0]) return fail(c, 404, "not_found", "Action not found");
  const token = randomToken(32);
  const id = uuid();
  const expiresAt = new Date(Date.now() + body.data.expiresInDays * 86_400_000).toISOString();
  await db()`
    INSERT INTO verification_links (id, org_id, environment_id, action_id, token_hash, expires_at, created_by)
    VALUES (${id}, ${s.org.id}, ${action[0].environment_id as string}, ${body.data.actionId}, ${sha256(token)}, ${expiresAt}, ${s.user.id})
  `;
  await audit({
    orgId: s.org.id,
    actorUserId: s.user.id,
    action: "verification_link.created",
    target: id,
    details: { actionId: body.data.actionId, expiresAt },
  });
  void emitWebhook(s.org.id, "verification_link.created", {
    verificationLinkId: id,
    actionId: body.data.actionId,
    expiresAt,
  });
  return c.json(
    {
      id,
      actionId: body.data.actionId,
      expiresAt,
      url: `${verifyBaseUrl}/verify/${token}`,
    },
    201,
  );
});

routes.delete("/v1/verification-links/:id", requireRole("owner", "admin", "member"), async (c) => {
  const s = session(c);
  const result = await db()`
    UPDATE verification_links SET revoked_at = now()
     WHERE id = ${c.req.param("id")} AND org_id = ${s.org.id} AND revoked_at IS NULL
  `;
  return c.json({ revoked: result.count > 0 });
});

// ── Helpers ────────────────────────────────────────────────────────────────

function actionSummary(row: Record<string, any>) {
  return {
    actionId: row.action_id,
    environmentId: row.environment_id,
    agentId: row.agent_id,
    principalId: row.principal_id,
    tool: row.tool,
    decision: row.decision,
    outcomeStatus: row.outcome_status,
    policyId: row.policy_id,
    policyVersion: row.policy_version,
    policyHash: row.policy_hash,
    credentialIssuer: row.credential_issuer,
    credentialThumbprint: row.credential_thumbprint,
    receiptId: row.receipt_id,
    createdAt: row.created_at,
    completedAt: row.completed_at,
    verified: row.verified,
  };
}
