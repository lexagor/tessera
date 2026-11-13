import { createHmac } from "node:crypto";

import { decryptSecret, encryptSecret, randomToken, uuid } from "./crypto.js";
import { db, withAdminContext, withDetachedAdminContext } from "./db.js";
import { env, isProduction } from "./env.js";
import { recordWebhookDelivered, recordWebhookFailed } from "./metrics.js";
import { isPrivateHostname, safeWebhookPost } from "./safe-webhook.js";

export const WEBHOOK_EVENTS = [
  "action.created",
  "action.completed",
  "action.denied",
  "verification_link.created",
  "evidence_pack.created",
  "agent_key.created",
  "agent_key.revoked",
  "environment.created",
  "policy.upserted",
] as const;

export type WebhookEvent = (typeof WEBHOOK_EVENTS)[number];

export function signWebhook(secret: string, timestamp: string, body: string): string {
  return createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
}

export function validateWebhookUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("Webhook URL is not valid");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Webhook URL must use http or https");
  }
  if (url.username || url.password) {
    throw new Error("Webhook URL must not contain credentials");
  }
  if (isProduction && url.protocol !== "https:") {
    throw new Error("Webhook URL must use https in production");
  }
  if (!env.ALLOW_PRIVATE_WEBHOOKS && isPrivateHostname(url.hostname)) {
    throw new Error("Private webhook hosts are not allowed");
  }
  return url.toString();
}

export async function createWebhookEndpoint(input: {
  orgId: string;
  url: string;
  events: string[];
}): Promise<{ id: string; secret: string }> {
  const url = validateWebhookUrl(input.url);
  const events = input.events.length ? input.events : ["*"];
  const allowed = new Set<string>(["*", ...WEBHOOK_EVENTS]);
  for (const event of events) {
    if (!allowed.has(event)) throw new Error(`Unknown webhook event '${event}'`);
  }
  const id = uuid();
  const secret = `whsec_${randomToken(24)}`;
  await db()`
    INSERT INTO webhook_endpoints (id, org_id, url, secret_enc, events)
    VALUES (${id}, ${input.orgId}, ${url}, ${encryptSecret(secret)}, ${db().array(events)})
  `;
  return { id, secret };
}

export async function emitWebhook(
  orgId: string,
  event: WebhookEvent,
  data: Record<string, unknown>,
): Promise<void> {
  let enqueued = false;
  try {
    await withDetachedAdminContext(async () => {
      const endpoints = await db()`
        SELECT id FROM webhook_endpoints
         WHERE org_id = ${orgId}
           AND active = true
           AND (events @> ARRAY['*']::text[] OR events @> ARRAY[${event}]::text[])
      `;
      if (endpoints.length === 0) return;
      const payload = {
        event,
        createdAt: new Date().toISOString(),
        data,
      };
      for (const endpoint of endpoints) {
        await db()`
          INSERT INTO webhook_deliveries (id, endpoint_id, org_id, event, payload)
          VALUES (${uuid()}, ${endpoint.id as string}, ${orgId}, ${event}, ${db().json(payload as never)})
        `;
      }
      enqueued = true;
    });
    if (enqueued) {
      void withAdminContext(processWebhookDeliveries).catch((error) => {
        console.error("webhook worker error", error);
      });
    }
  } catch (error) {
    console.error("webhook enqueue failed", error);
  }
}

let running = false;
const workerId = `${process.pid}-${randomToken(8)}`;
const LEASE_SECONDS = 120;

export async function cleanupWebhookDeliveries(): Promise<void> {
  const days = env.WEBHOOK_RETENTION_DAYS;
  if (days <= 0) return;
  await db()`
    DELETE FROM webhook_deliveries
     WHERE status IN ('delivered', 'failed')
       AND created_at < now() - make_interval(days => ${days})
  `;
}

export async function processWebhookDeliveries(): Promise<void> {
  if (running) return;
  running = true;
  try {
    await db()`
      UPDATE webhook_deliveries
         SET status = 'pending', locked_by = NULL, locked_until = NULL
       WHERE status = 'delivering' AND (locked_until IS NULL OR locked_until < now())
    `;

    const rows = await db()`
      WITH due AS (
        SELECT id
          FROM webhook_deliveries
         WHERE status = 'pending'
           AND next_attempt_at <= now()
         ORDER BY next_attempt_at
         FOR UPDATE SKIP LOCKED
         LIMIT 20
      ), claimed AS (
        UPDATE webhook_deliveries d
           SET status = 'delivering',
               locked_by = ${workerId},
               locked_until = now() + make_interval(secs => ${LEASE_SECONDS})
          FROM due
         WHERE d.id = due.id
         RETURNING d.id
      )
      SELECT d.id, d.attempts, d.payload, e.url, e.secret_enc
        FROM webhook_deliveries d
        JOIN webhook_endpoints e ON e.id = d.endpoint_id
        JOIN claimed c ON c.id = d.id
       WHERE e.active = true
    `;

    for (const row of rows) {
      const body = JSON.stringify(row.payload);
      const timestamp = Math.floor(Date.now() / 1000).toString();
      try {
        const signature = signWebhook(
          decryptSecret(row.secret_enc as string),
          timestamp,
          body,
        );
        await safeWebhookPost({
          url: row.url as string,
          headers: {
            "content-type": "application/json",
            "x-tessera-event": (row.payload as { event?: string }).event ?? "unknown",
            "x-tessera-timestamp": timestamp,
            "x-tessera-signature": `sha256=${signature}`,
            "user-agent": "Tessera-Webhooks/0.1",
          },
          body,
        });
        recordWebhookDelivered();
        await db()`
          UPDATE webhook_deliveries
             SET status = 'delivered',
                 attempts = attempts + 1,
                 delivered_at = now(),
                 locked_by = NULL,
                 locked_until = NULL,
                 last_error = null
           WHERE id = ${row.id as string} AND locked_by = ${workerId}
        `;
      } catch (error) {
        recordWebhookFailed();
        const attempts = Number(row.attempts) + 1;
        const failed = attempts >= 5;
        const delay = Math.min(2 ** attempts, 300);
        await db()`
          UPDATE webhook_deliveries
             SET status = ${failed ? "failed" : "pending"},
                 attempts = ${attempts},
                 next_attempt_at = now() + make_interval(secs => ${delay}),
                 locked_by = NULL,
                 locked_until = NULL,
                 last_error = ${error instanceof Error ? error.message : String(error)}
           WHERE id = ${row.id as string} AND locked_by = ${workerId}
        `;
      }
    }
  } finally {
    running = false;
  }
}
