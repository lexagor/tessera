import type { Context, MiddlewareHandler } from "hono";
import { createClient } from "redis";

import type { AppEnv } from "./auth.js";
import { env } from "./env.js";
import { recordRateLimited } from "./metrics.js";

interface Window {
  count: number;
  resetAt: number;
}

export interface RateLimitDecision {
  allowed: boolean;
  retryAfterSeconds: number;
}

/** Bounded fixed-window limiter. One process; replace with Redis for multi-replica API. */
export class MinuteRateLimiter {
  private windows = new Map<string, Window>();
  private readonly maxKeys: number;

  constructor(maxKeys = 50_000) {
    this.maxKeys = Math.max(1, maxKeys);
  }

  allow(key: string, limit: number, now = Date.now()): RateLimitDecision {
    if (this.windows.size >= this.maxKeys) this.evict(now);
    const current = this.windows.get(key);
    if (!current || current.resetAt <= now) {
      this.windows.set(key, { count: 1, resetAt: now + 60_000 });
      return { allowed: true, retryAfterSeconds: 0 };
    }
    if (current.count >= limit) {
      return {
        allowed: false,
        retryAfterSeconds: Math.max(1, Math.ceil((current.resetAt - now) / 1000)),
      };
    }
    current.count += 1;
    return { allowed: true, retryAfterSeconds: 0 };
  }

  private evict(now: number): void {
    for (const [key, window] of this.windows) {
      if (window.resetAt <= now) this.windows.delete(key);
    }
    while (this.windows.size >= this.maxKeys) {
      const oldest = this.windows.keys().next().value;
      if (oldest === undefined) break;
      this.windows.delete(oldest);
    }
  }
}

export interface RateLimiterLike {
  allow(key: string, limit: number, now?: number): RateLimitDecision | Promise<RateLimitDecision>;
}

/** Redis-backed limiter with a local fallback. One Redis connection is opened lazily. */
export class RedisRateLimiter implements RateLimiterLike {
  private client: ReturnType<typeof createClient> | null = null;
  private connecting: Promise<void> | null = null;
  private retryAt = 0;
  private warned = false;
  private readonly fallback = new MinuteRateLimiter();

  constructor(private readonly url: string | undefined = env.REDIS_URL) {}

  private async ensureClient(): Promise<ReturnType<typeof createClient> | null> {
    if (!this.url) return null;
    if (this.client?.isOpen) return this.client;
    const now = Date.now();
    if (now < this.retryAt) return null;
    if (!this.connecting) {
      const client = createClient({ url: this.url });
      client.on("error", (error) => {
        if (!this.warned) {
          console.warn("redis rate limiter error", error);
          this.warned = true;
        }
      });
      this.connecting = client
        .connect()
        .then(() => {
          this.client = client;
          this.warned = false;
        })
        .catch((error) => {
          this.retryAt = Date.now() + 30_000;
          this.client = null;
          void client.disconnect();
          throw error;
        })
        .finally(() => {
          this.connecting = null;
        });
    }
    try {
      await this.connecting;
      return this.client;
    } catch {
      return null;
    }
  }

  async close(): Promise<void> {
    if (this.client?.isOpen) {
      await this.client.quit().catch(() => {});
      this.client = null;
    }
  }

  async allow(key: string, limit: number, now = Date.now()): Promise<RateLimitDecision> {
    const client = await this.ensureClient();
    if (!client) return this.fallback.allow(key, limit, now);
    const window = Math.floor(now / 60_000);
    const redisKey = `tessera:api:rl:${key}:${window}`;
    try {
      const count = await client.incr(redisKey);
      if (count === 1) await client.expire(redisKey, 60);
      if (count <= limit) return { allowed: true, retryAfterSeconds: 0 };
      return {
        allowed: false,
        retryAfterSeconds: Math.max(1, 60 - Math.floor((now % 60_000) / 1000)),
      };
    } catch (error) {
      if (!this.warned) {
        console.warn("redis rate limiter failed, using local fallback", error);
        this.warned = true;
      }
      this.client = null;
      this.retryAt = Date.now() + 30_000;
      void client.disconnect();
      return this.fallback.allow(key, limit, now);
    }
  }
}

const defaultLimiter = new RedisRateLimiter();

export interface RateLimitOptions {
  name: string;
  limit: number;
  key: (c: Context) => string;
  limiter?: RateLimiterLike;
}

export function rateLimit(options: RateLimitOptions): MiddlewareHandler<AppEnv> {
  const limiter = options.limiter ?? defaultLimiter;
  return async (c, next) => {
    if (process.env.NODE_ENV === "test" && process.env.RATE_LIMIT_TEST !== "1") {
      return next();
    }
    const decision = await limiter.allow(options.key(c), options.limit);
    if (!decision.allowed) {
      recordRateLimited();
      c.header("retry-after", String(decision.retryAfterSeconds));
      return c.json(
        {
          error: {
            code: "rate_limited",
            message: `Too many ${options.name} requests; retry later`,
          },
        },
        429,
      );
    }
    await next();
  };
}

export async function closeRateLimiter(): Promise<void> {
  await defaultLimiter.close();
}
