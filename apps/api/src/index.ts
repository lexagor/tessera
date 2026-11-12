import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";

import { type AppEnv, requireSession } from "./auth.js";
import { authRoutes } from "./auth-routes.js";
import { billingWebhookRoutes } from "./billing.js";
import { db, migrate } from "./db.js";
import { env } from "./env.js";
import { openapi } from "./openapi.js";
import { routes } from "./routes.js";
import { processWebhookDeliveries } from "./webhooks.js";

export const app = new Hono<AppEnv>();

app.use("*", async (c, next) => {
  await next();
  c.header("x-content-type-options", "nosniff");
  c.header("cache-control", "no-store");
});

app.onError((error, c) => {
  if (error instanceof HTTPException) {
    return c.json(
      { error: { code: "http_error", message: error.message } },
      error.status,
    );
  }
  console.error("unhandled API error", error);
  return c.json(
    {
      error: {
        code: "internal_error",
        message: "Internal error",
        requestId: c.res.headers.get("x-request-id") ?? undefined,
      },
    },
    500,
  );
});

app.notFound((c) =>
  c.json({ error: { code: "not_found", message: "Route not found" } }, 404),
);

app.get("/healthz", (c) => c.json({ status: "ok", service: "tessera-api", version: "0.1.0" }));
app.get("/readyz", async (c) => {
  try {
    await db()`SELECT 1`;
    const broker = await fetch(`${env.BROKER_URL.replace(/\/$/, "")}/healthz`, {
      signal: AbortSignal.timeout(3_000),
    });
    if (!broker.ok) {
      return c.json({ status: "degraded", database: true, broker: false }, 503);
    }
    return c.json({ status: "ok", database: true, broker: true });
  } catch {
    return c.json({ status: "degraded", database: false, broker: false }, 503);
  }
});
app.get("/openapi.json", (c) => c.json(openapi));
app.get("/v1/openapi.json", (c) => c.json(openapi));

app.route("/", billingWebhookRoutes);
app.route("/", authRoutes);
app.route("/", routes);

app.get("/v1/session", requireSession, (c) => {
  const session = c.get("session");
  return c.json({
    user: session.user,
    org: session.org,
    role: session.role,
  });
});

if (process.env.NODE_ENV !== "test") {
  await migrate();
  setInterval(() => {
    void processWebhookDeliveries().catch((error) => {
      console.error("webhook worker failed", error);
    });
  }, 5_000).unref();
  serve({ fetch: app.fetch, port: env.API_PORT }, (info) => {
    console.log(`tessera api listening on :${info.port}`);
  });
}

export default app;
