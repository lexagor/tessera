# KMS/HSM Benchmark

**Status:** harness and test plan. No live cloud KMS/HSM benchmark has been run.

The broker's `HttpKmsSigner` sends a 32-byte digest to an operator-provided bridge and expects
`{"signature":"0x<r||s||v>","address":"0x..."}`. The benchmark measures that bridge, not the
local signer.

## Run

```bash
KMS_SIGNER_URL=https://kms-bridge.staging.example \
KMS_SIGNER_ADDRESS=0x... \
KMS_SIGNER_TOKEN=... \
REQUESTS=2000 CONCURRENCY=16 \
node scripts/kms-bench.mjs
```

The script validates signature shape and the configured signer address, and fails if any request
errors. It prints p50/p95/p99 latency, throughput, and failures. Do not print the token.

## Test matrix

| Test | Pass condition |
|---|---|
| Steady signing | Zero malformed signatures, p95 within the staging budget |
| Bridge timeout | Broker fails closed; no unsigned receipt |
| Bridge 5xx | Broker fails closed and surfaces an error |
| Malformed signature | Rejected; no receipt is appended |
| Wrong signer address | Rejected by verification/configuration |
| Key rotation | New signer accepted, old signer in history for verification |
| Burst/concurrency | No unbounded queue, memory growth, or duplicate signing |
| Restore after bridge outage | Broker resumes only after a valid signature |

## What to record

- KMS/HSM provider, key spec, region, and bridge version.
- Broker image digest, configuration hash, host/instance type, and network path.
- Requests, concurrency, p50/p95/p99, failures, and any retries.
- Whether signing is in the request path or asynchronous, and the resulting action latency.
- Incident/failure behavior and the rotation drill result.

Do not publish a production latency or availability guarantee from a single staging run. The
live deployment still uses the in-process signer; see [`kms-production.md`](kms-production.md).
