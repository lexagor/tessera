import assert from "node:assert/strict";
import { test } from "node:test";

process.env.NODE_ENV = "test";
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? "postgres://unused";

const { MinuteRateLimiter, RedisRateLimiter } = await import("../src/rate-limit.js");

test("minute limiter allows the budget then reports retry-after", () => {
  const limiter = new MinuteRateLimiter();
  const now = 1_000_000;
  assert.equal(limiter.allow("a", 2, now).allowed, true);
  assert.equal(limiter.allow("a", 2, now).allowed, true);
  const blocked = limiter.allow("a", 2, now);
  assert.equal(blocked.allowed, false);
  assert.ok(blocked.retryAfterSeconds >= 1);
  assert.equal(limiter.allow("b", 2, now).allowed, true);
});

test("minute limiter resets after the window", () => {
  const limiter = new MinuteRateLimiter();
  assert.equal(limiter.allow("a", 1, 1_000_000).allowed, true);
  assert.equal(limiter.allow("a", 1, 1_000_001).allowed, false);
  assert.equal(limiter.allow("a", 1, 1_060_001).allowed, true);
});

test("redis limiter without a URL falls back to local enforcement", async () => {
  const limiter = new RedisRateLimiter(undefined);
  assert.equal((await limiter.allow("a", 1, 1_000_000)).allowed, true);
  assert.equal((await limiter.allow("a", 1, 1_000_001)).allowed, false);
  await limiter.close();
});
