#!/usr/bin/env node
/**
 * Small dependency-free authorize load harness. Use a staging environment and a dedicated
 * agent key; this script never prints the key.
 */
const base = (process.env.TESSERA_BASE_URL ?? "").replace(/\/$/, "");
const key = process.env.TESSERA_AGENT_KEY ?? "";
const agentId = process.env.TESSERA_AGENT_ID ?? "load-agent";
const userId = process.env.TESSERA_USER_ID ?? "load-user";
const tool = process.env.TESSERA_TOOL ?? "stripe.refunds.create";
const concurrency = Math.max(1, Number(process.env.CONCURRENCY ?? 16));
const total = Math.max(1, Number(process.env.REQUESTS ?? 500));
const timeoutMs = Math.max(1_000, Number(process.env.TIMEOUT_MS ?? 20_000));

if (!base || !key) {
  console.error("Set TESSERA_BASE_URL and TESSERA_AGENT_KEY");
  process.exit(2);
}

const latencies = [];
let failures = 0;
let next = 0;
let started = 0;

async function one(index) {
  const startedAt = performance.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${base}/v1/authorize`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": key,
      },
      body: JSON.stringify({
        agentId,
        userId,
        tool,
        intent: `load-test ${index}`,
        args: { loadTest: index },
        requestedScopes: [],
      }),
      signal: controller.signal,
    });
    if (!response.ok) failures += 1;
    await response.arrayBuffer();
    latencies.push(performance.now() - startedAt);
  } catch {
    failures += 1;
    latencies.push(performance.now() - startedAt);
  } finally {
    clearTimeout(timer);
  }
}

async function worker() {
  for (;;) {
    const index = next++;
    if (index >= total) return;
    await one(index);
  }
}

const startedAt = performance.now();
started = Date.now();
await Promise.all(Array.from({ length: concurrency }, () => worker()));
const elapsed = performance.now() - startedAt;
latencies.sort((a, b) => a - b);
const percentile = (p) => latencies[Math.min(latencies.length - 1, Math.floor(latencies.length * p))] ?? 0;
console.log(JSON.stringify({
  base,
  requests: total,
  concurrency,
  failures,
  success: total - failures,
  elapsedMs: Math.round(elapsed),
  requestsPerSecond: Math.round((total / elapsed) * 1000),
  latencyMs: {
    p50: Math.round(percentile(0.5)),
    p95: Math.round(percentile(0.95)),
    p99: Math.round(percentile(0.99)),
    max: Math.round(latencies.at(-1) ?? 0),
  },
  startedAt: new Date(started).toISOString(),
}, null, 2));
process.exit(failures > 0 ? 1 : 0);
