#!/usr/bin/env node
/**
 * Benchmark a KMS/HSM bridge that implements Tessera's signer contract:
 *   POST {KMS_SIGNER_URL}/sign {"digest":"0x<32-byte hex>"}
 *   -> {"signature":"0x<r||s||v>","address":"0x..."}
 *
 * This measures bridge latency only; it is not a production SLA. Use a staging signer/key.
 */
const url = (process.env.KMS_SIGNER_URL ?? "").replace(/\/$/, "");
const expected = (process.env.KMS_SIGNER_ADDRESS ?? "").toLowerCase();
const token = process.env.KMS_SIGNER_TOKEN ?? "";
const requests = Math.max(1, Number(process.env.REQUESTS ?? 200));
const concurrency = Math.max(1, Number(process.env.CONCURRENCY ?? 8));
const timeoutMs = Math.max(1_000, Number(process.env.TIMEOUT_MS ?? 10_000));
if (!url) {
  console.error("Set KMS_SIGNER_URL (and optionally KMS_SIGNER_ADDRESS/KMS_SIGNER_TOKEN)");
  process.exit(2);
}

const digest = `0x${"11".repeat(32)}`;
const latencies = [];
let failures = 0;
let next = 0;

async function one() {
  const started = performance.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${url}/sign`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ digest }),
      signal: controller.signal,
    });
    const body = await response.json().catch(() => null);
    const signature = body?.signature;
    if (!response.ok || typeof signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
      failures += 1;
    } else if (expected && String(body?.address ?? "").toLowerCase() !== expected) {
      failures += 1;
    }
  } catch {
    failures += 1;
  } finally {
    clearTimeout(timer);
    latencies.push(performance.now() - started);
  }
}

async function worker() {
  for (;;) {
    const index = next++;
    if (index >= requests) return;
    await one();
  }
}

const started = performance.now();
await Promise.all(Array.from({ length: concurrency }, () => worker()));
const elapsed = performance.now() - started;
latencies.sort((a, b) => a - b);
const pct = (p) => latencies[Math.min(latencies.length - 1, Math.floor(latencies.length * p))] ?? 0;
console.log(JSON.stringify({
  signer: url,
  requests,
  concurrency,
  failures,
  elapsedMs: Math.round(elapsed),
  requestsPerSecond: Math.round((requests / elapsed) * 1000),
  latencyMs: {
    p50: Math.round(pct(0.5)),
    p95: Math.round(pct(0.95)),
    p99: Math.round(pct(0.99)),
    max: Math.round(latencies.at(-1) ?? 0),
  },
}, null, 2));
process.exit(failures > 0 ? 1 : 0);
