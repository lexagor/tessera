#!/usr/bin/env node
const endpoint = (process.env.TESSERA_ENDPOINT ?? "http://127.0.0.1:8787").replace(/\/$/, "");
const apiKey = process.env.TESSERA_API_KEY ?? "tsk_demo_local";
const requests = Number(process.env.BENCH_REQUESTS ?? 200);
const concurrency = Number(process.env.BENCH_CONCURRENCY ?? 16);
const agents = Number(process.env.BENCH_AGENTS ?? 1);
const agentPrefix = process.env.BENCH_AGENT_PREFIX ?? "benchmark-agent";
const authorityToken = process.env.TESSERA_AUTHORITY_TOKEN;
const verifyChains = process.env.BENCH_VERIFY_CHAINS !== "0";

for (const [name, value] of [
  ["BENCH_REQUESTS", requests],
  ["BENCH_CONCURRENCY", concurrency],
  ["BENCH_AGENTS", agents],
]) {
  if (!Number.isFinite(value) || value < 1) throw new Error(`${name} must be >= 1`);
}

function percentile(values, p) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, index)];
}

function agentFor(index) {
  return agents === 1 ? agentPrefix : `${agentPrefix}-${index % agents}`;
}

async function one(index) {
  const started = performance.now();
  const agentId = agentFor(index);
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
      intent: "concurrency benchmark",
      args: { amount: 10, charge: `ch_bench_${index}` },
      ...(authorityToken ? { authorityToken } : {}),
    }),
  });
  const elapsed = performance.now() - started;
  await response.arrayBuffer();
  return { status: response.status, elapsed, agentId };
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

const chainChecks = [];
if (verifyChains) {
  for (let index = 0; index < agents; index += 1) {
    const agentId = agentFor(index);
    const response = await fetch(`${endpoint}/v1/chain/${encodeURIComponent(agentId)}`, {
      headers: { authorization: `Bearer ${apiKey}` },
    });
    const body = await response.json().catch(() => ({}));
    chainChecks.push({
      agentId,
      status: response.status,
      length: body.length ?? null,
      verified: body.verified ?? null,
    });
  }
}

console.log(JSON.stringify({
  endpoint,
  requests,
  concurrency,
  agents,
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
  chainChecks,
}, null, 2));
