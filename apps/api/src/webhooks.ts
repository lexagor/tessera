import { createHmac } from "node:crypto";

import { decryptSecret, encryptSecret, randomToken, uuid } from "./crypto.js";
import { db } from "./db.js";
import { env, isProduction } from "./env.js";

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

function isPrivateHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (host === "localhost" || host === "0.0.0.0" || host === "::1" || host.endsWith(".local")) {
    return true;
  }
  if (host === "127.0.0.1" || host.startsWith("127.")) return true;
  if (host.startsWith("10.") || host.startsWith("192.168.")) return true;
  const match = host.match(/^172\.(\d+)\./);
  if (match) {
    const octet = Number(match[1]);
    if (octet >= 16 && octet <= 31) return true;
  }
  return false;
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
  if (isProduction && url.protocol !== "https:") {
    throw new Error("Webhook URL must use https in production");
  }
  if (!env.ALLOW_PRIVATE_WEBHOOKS && isPrivateHost(url.hostname)) {
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
  try {
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
    void processWebhookDeliveries().catch((error) => {
      console.error("webhook worker error", error);
    });
  } catch (error) {
    console.error("webhook enqueue failed", error);
  }
}

let running = false;

export async function processWebhookDeliveries(): Promise<void> {
  if (running) return;
  running = true;
  try {
    const rows = await db()`
      SELECT d.id, d.attempts, d.payload, e.url, e.secret_enc
        FROM webhook_deliveries d
        JOIN webhook_endpoints e ON e.id = d.endpoint_id
       WHERE d.status = 'pending'
         AND d.next_attempt_at <= now()
         AND e.active = true
       ORDER BY d.next_attempt_at
       LIMIT 20
    `;
    for (const row of rows) {
      const body = JSON.stringify(row.payload);
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const signature = signWebhook(
        decryptSecret(row.secret_enc as string),
        timestamp,
        body,
      );
      try {
        const response = await fetch(row.url as string, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-tessera-event": (row.payload as { event?: string }).event ?? "unknown",
            "x-tessera-timestamp": timestamp,
            "x-tessera-signature": `sha256=${signature}`,
            "user-agent": "Tessera-Webhooks/0.1",
          },
          body,
          signal: AbortSignal.timeout(10_000),
        });
        if (!response.ok) throw new Error(`endpoint returned ${response.status}`);
        await db()`
          UPDATE webhook_deliveries
             SET status = 'delivered',
                 attempts = attempts + 1,
                 delivered_at = now(),
                 last_error = null
           WHERE id = ${row.id as string}
        `;
      } catch (error) {
        const attempts = Number(row.attempts) + 1;
        const failed = attempts >= 5;
        const delay = Math.min(2 ** attempts, 300);
        await db()`
          UPDATE webhook_deliveries
             SET status = ${failed ? "failed" : "pending"},
                 attempts = ${attempts},
                 next_attempt_at = now() + make_interval(secs => ${delay}),
                 last_error = ${error instanceof Error ? error.message : String(error)}
           WHERE id = ${row.id as string}
        `;
      }
    }
  } finally {
    running = false;
  }
}
