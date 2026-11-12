#!/usr/bin/env node
const endpoint = (process.env.TESSERA_ENDPOINT ?? "http://127.0.0.1:8787").replace(/\/$/, "");
const apiKey = process.env.TESSERA_API_KEY ?? "tsk_demo_local";
const requests = Number(process.env.BENCH_REQUESTS ?? 200);
const concurrency = Number(process.env.BENCH_CONCURRENCY ?? 4);
const agentId = process.env.BENCH_AGENT_ID ?? "benchmark-agent";
if (!Number.isFinite(requests) || requests < 1) throw new Error("BENCH_REQUESTS must be >= 1");
if (!Number.isFinite(concurrency) || concurrency < 1) throw new Error("BENCH_CONCURRENCY must be >= 1");

function percentile(values, p) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, index)];
}

async function one(index) {
  const started = performance.now();
  const response = await fetch(`${endpoint}/v1/authorize`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      agentId,
      userId: "benchmark-user",
      tool: "stripe.refunds.create",
      intent: "benchmark authorize latency",
      args: { amount: 10, charge: `ch_bench_${index}` },
    }),
  });
  const elapsed = performance.now() - started;
  await response.arrayBuffer();
  return { status: response.status, elapsed };
}

let next = 0;
const latencies = [];
const statuses = new Map();
const workers = Array.from({ length: concurrency }, async () => {
  while (true) {
    const index = next++;
    if (index >= requests) return;
    try {
      const result = await one(index);
      latencies.push(result.elapsed);
      statuses.set(result.status, (statuses.get(result.status) ?? 0) + 1);
    } catch (error) {
      statuses.set("error", (statuses.get("error") ?? 0) + 1);
      console.error(error);
    }
  }
});
const started = performance.now();
await Promise.all(workers);
const wall = performance.now() - started;
const mean = latencies.reduce((sum, value) => sum + value, 0) / Math.max(1, latencies.length);
console.log(JSON.stringify({
  endpoint,
  requests,
  concurrency,
  wallMs: Number(wall.toFixed(1)),
  throughputPerSecond: Number(((latencies.length / wall) * 1000).toFixed(1)),
  statuses: Object.fromEntries([...statuses.entries()].map(([key, value]) => [String(key), value])),
  latencyMs: {
    mean: Number(mean.toFixed(2)),
    p50: Number(percentile(latencies, 50).toFixed(2)),
    p95: Number(percentile(latencies, 95).toFixed(2)),
    p99: Number(percentile(latencies, 99).toFixed(2)),
    min: Number(Math.min(...latencies).toFixed(2)),
    max: Number(Math.max(...latencies).toFixed(2)),
  },
}, null, 2));
