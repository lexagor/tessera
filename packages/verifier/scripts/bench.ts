import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";

import { verifyReceipt } from "../src/index.js";

const fixture = JSON.parse(
  readFileSync(new URL("../../receipt-schema/fixtures/receipt-v2-signed.json", import.meta.url), "utf8"),
) as {
  domain: { chainId: number; verifyingContract: string };
  expectedSigner: string;
  receipt: Record<string, unknown>;
};
const iterations = Number(process.env.BENCH_ITERATIONS ?? 10_000);
const receiptBytes = Buffer.byteLength(JSON.stringify(fixture.receipt));

for (let i = 0; i < 100; i += 1) {
  const result = verifyReceipt(fixture.receipt, fixture.domain, fixture.expectedSigner);
  if (!result.valid) throw new Error("fixture failed verification");
}

const latencies: number[] = [];
let valid = 0;
for (let i = 0; i < iterations; i += 1) {
  const started = performance.now();
  const result = verifyReceipt(fixture.receipt, fixture.domain, fixture.expectedSigner);
  latencies.push(performance.now() - started);
  if (result.valid) valid += 1;
}
latencies.sort((a, b) => a - b);
const pick = (p: number) => latencies[Math.min(latencies.length - 1, Math.ceil((p / 100) * latencies.length) - 1)] ?? 0;
const mean = latencies.reduce((sum, value) => sum + value, 0) / Math.max(1, latencies.length);
console.log(JSON.stringify({
  iterations,
  receiptBytes,
  valid,
  latencyMs: {
    mean: Number(mean.toFixed(4)),
    p50: Number(pick(50).toFixed(4)),
    p95: Number(pick(95).toFixed(4)),
    p99: Number(pick(99).toFixed(4)),
    min: Number((latencies[0] ?? 0).toFixed(4)),
    max: Number((latencies[latencies.length - 1] ?? 0).toFixed(4)),
  },
}, null, 2));
