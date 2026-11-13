import { randomUUID } from "node:crypto";

import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { HTTPException } from "hono/http-exception";
import { timeout } from "hono/timeout";

import { type AppEnv, cleanupSessions, requireSession } from "./auth.js";
import { authRoutes } from "./auth-routes.js";
import { billingWebhookRoutes } from "./billing.js";
import { assertProductionDatabaseRole, closeDb, db, migrate, withAdminContext } from "./db.js";
import { env, isProduction } from "./env.js";
import { recordRequest, renderMetrics } from "./metrics.js";
import { openapi } from "./openapi.js";
import { routes } from "./routes.js";
import { scimRoutes } from "./scim.js";
import { closeRateLimiter } from "./rate-limit.js";
import { cleanupWebhookDeliveries, processWebhookDeliveries } from "./webhooks.js";

export const app = new Hono<AppEnv>();

app.use("*", async (c, next) => {
  const supplied = c.req.header("x-request-id");
  const requestId = supplied && /^[A-Za-z0-9._-]{1,128}$/.test(supplied) ? supplied : randomUUID();
  c.header("x-request-id", requestId);
  c.header("x-content-type-options", "nosniff");
  c.header("cache-control", "no-store");
  c.header("referrer-policy", "strict-origin-when-cross-origin");
  c.header("x-frame-options", "DENY");
  c.header("x-permitted-cross-domain-policies", "none");
  c.header("permissions-policy", "camera=(), microphone=(), geolocation=()");
  c.header("cross-origin-opener-policy", "same-origin");
  c.header("cross-origin-resource-policy", "same-origin");
  c.header("content-security-policy", "default-src 'none'; frame-ancestors 'none'");
  if (isProduction) {
    c.header("strict-transport-security", "max-age=31536000; includeSubDomains");
  }
  const started = performance.now();
  await next();
  recordRequest(c.res.status, performance.now() - started);
  if (process.env.NODE_ENV !== "test") {
    console.log(
      JSON.stringify({
        level: "info",
        service: "tessera-api",
        requestId,
        method: c.req.method,
        path: c.req.path,
        status: c.res.status,
        durationMs: Math.round(performance.now() - started),
      }),
    );
  }
});

app.use("*", timeout(env.REQUEST_TIMEOUT_MS));
app.use(
  "*",
  bodyLimit({
    maxSize: env.MAX_REQUEST_BYTES,
    onError: (c) =>
      c.json({ error: { code: "payload_too_large", message: "Request body is too large" } }, 413),
  }),
);

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

app.get("/healthz", (c) => c.json({ status: "ok", service: "tessera-api", version: "0.1.3" }));
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
app.get("/metrics", (c) => c.text(renderMetrics()));

app.route("/", billingWebhookRoutes);
app.route("/", authRoutes);
app.route("/", routes);
app.route("/scim/v2", scimRoutes);

app.get("/v1/session", requireSession, (c) => {
  const session = c.get("session");
  return c.json({
    user: session.user,
    org: session.org,
    role: session.role,
  });
});

if (process.env.NODE_ENV !== "test") {
  await assertProductionDatabaseRole();
  await migrate();
  void withAdminContext(cleanupSessions).catch((error) => {
    console.error("session cleanup failed", error);
  });
  void withAdminContext(cleanupWebhookDeliveries).catch((error) => {
    console.error("webhook cleanup failed", error);
  });
  setInterval(() => {
    void withAdminContext(cleanupSessions).catch((error) => {
      console.error("session cleanup failed", error);
    });
  }, 3_600_000).unref();
  setInterval(() => {
    void withAdminContext(processWebhookDeliveries).catch((error) => {
      console.error("webhook worker failed", error);
    });
  }, 5_000).unref();
  setInterval(() => {
    void withAdminContext(cleanupWebhookDeliveries).catch((error) => {
      console.error("webhook cleanup failed", error);
    });
  }, 3_600_000).unref();
  const httpServer = serve(
    {
      fetch: app.fetch,
      port: env.API_PORT,
      serverOptions: {
        headersTimeout: 15_000,
        requestTimeout: env.REQUEST_TIMEOUT_MS + 5_000,
        keepAliveTimeout: 5_000,
      },
    },
    (info) => {
      console.log(`tessera api listening on :${info.port}`);
    },
  );

  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) {
      process.exit(1);
    }
    shuttingDown = true;
    console.log(`tessera api received ${signal}; shutting down`);
    const connections = httpServer as unknown as {
      closeAllConnections?: () => void;
      closeIdleConnections?: () => void;
    };
    const forceClose = setTimeout(() => connections.closeAllConnections?.(), 10_000);
    forceClose.unref();
    await new Promise<void>((resolve) => {
      httpServer.close(() => resolve());
      connections.closeIdleConnections?.();
    });
    clearTimeout(forceClose);
    await Promise.allSettled([closeDb(), closeRateLimiter()]);
    process.exit(0);
  };
  process.once("SIGTERM", () => void shutdown("SIGTERM"));
  process.once("SIGINT", () => void shutdown("SIGINT"));
}

export default app;
