# Load Testing

Local benchmarks are not production evidence. The load harness lives in
[`scripts/load/`](../scripts/load/) and targets a staging deployment with synthetic data.

## Safety

- Never run against production without an approved window and a rollback owner.
- Use a dedicated environment and agent key; do not reuse customer credentials.
- Set a hard request cap and stop on the first sustained 5xx or `readyz` failure.
- Do not generate evidence packs or webhook deliveries in the hot path unless that is the
  behavior under test.

## Authorize load

```bash
TESSERA_BASE_URL=https://staging.thetessera.xyz \
TESSERA_AGENT_KEY=tsk_staging_... \
TESSERA_AGENT_ID=load-agent \
TESSERA_USER_ID=load-user \
TESSERA_TOOL=stripe.refunds.create \
CONCURRENCY=32 REQUESTS=2000 \
node scripts/load/authorize.mjs
```

The script reports successful requests, errors, throughput, and p50/p95/p99 latency. It does
not print the key.

## Scenarios

| Scenario | Goal | Pass signal |
|---|---|---|
| Authorize steady | Broker + API + DB latency | p95 within the staging budget, zero 5xx |
| Authorize burst | Rate-limit behavior | predictable 429s, no cascading failure |
| Evidence export | Large archive memory/disk | no OOM, bounded disk, download verifies |
| Webhook fan-out | Lease/retry behavior | at-least-once, no duplicate side effects |
| Redis loss | Fail-closed or fallback | no auth bypass; documented degradation |

Record the image digests, host size, database size, concurrency, dataset, and results. Do not
publish a production SLA from a single staging run.
