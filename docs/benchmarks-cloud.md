# Cloud benchmark runbook

The committed benchmark numbers are local Apple M5 + mock issuer. Do not present them as a
production SLA. This runbook produces a real cloud baseline with Postgres and a KMS/HSM bridge.

## Target shape

| Component | Suggested baseline | Notes |
|---|---|---|
| Broker | `c7g.large` or `m7g.large` | 2 vCPU; build with `--release` |
| Postgres | `db.r7g.large` Multi-AZ | same region; TLS required |
| KMS/HSM bridge | operator-provided HTTPS service | set `KMS_SIGNER_URL` and `KMS_SIGNER_ADDRESS` |
| Load generator | separate `c7g.large` | use `scripts/bench-concurrency.mjs` |
| Issuer | mock Stripe | isolates broker/DB/KMS latency from provider latency |

Pin the broker image or commit SHA. Record the instance types, Postgres version, region, kernel,
Rust version, and whether TLS is terminated by a proxy.

## Setup

1. Provision Postgres. The broker applies its idempotent migrations at startup.

2. Build and start the broker with a stable signing key or the KMS bridge:

```bash
export DATABASE_URL=postgres://...
export BROKER_PORT=8787
export TESSERA_DEMO_ALLOW=0
export TESSERA_AUTHORITY_HMAC_SECRET="$(openssl rand -hex 32)"
export TESSERA_AUTHORITY_REQUIRE_TOKEN=1
export KMS_SIGNER_URL=https://kms-bridge.internal/sign
export KMS_SIGNER_ADDRESS=0x...
export STRIPE_API_BASE=http://mock-stripe:12111
export STRIPE_RESTRICTED_KEYS="charges_create=rk_test_cloud,refunds_create=rk_test_cloud"
export RUST_LOG=tessera_broker=warn
cargo build --release
./target/release/tessera-broker
```

3. Create an agent key through the control plane, or use the broker admin API with
   `TESSERA_ADMIN_TOKEN`. Use the key for both benchmark scripts.

## Runs

```bash
# Same-agent chain contention
BENCH_REQUESTS=2000 BENCH_CONCURRENCY=32 BENCH_AGENTS=1 \
TESSERA_ENDPOINT=https://broker-bench.example TESSERA_API_KEY=... \
pnpm bench:concurrency

# Multiple independent agents
BENCH_REQUESTS=4000 BENCH_CONCURRENCY=64 BENCH_AGENTS=32 \
TESSERA_ENDPOINT=https://broker-bench.example TESSERA_API_KEY=... \
pnpm bench:concurrency

# HTTP latency baseline
BENCH_REQUESTS=1000 BENCH_CONCURRENCY=8 \
TESSERA_ENDPOINT=https://broker-bench.example TESSERA_API_KEY=... \
pnpm bench:http

# Offline verification on the load generator
pnpm bench:verify
```

For each run, record the JSON output and check:

- `statuses` has no `5xx` or `error` entries.
- same-agent `chainChecks[0].length` equals successful authorizations
- every `chainChecks[*].verified` is `true`
- p95/p99 are reported, not only the mean
- the run is repeated 3 times and the median is reported

## Results template

| Run | Throughput | p50 | p95 | p99 | Errors | Chain verified |
|---|---:|---:|---:|---:|---:|---:|
| Cloud, mock issuer, same agent, concurrency 32 | TBD | TBD | TBD | TBD | TBD | TBD |
| Cloud, mock issuer, 32 agents, concurrency 64 | TBD | TBD | TBD | TBD | TBD | TBD |
| Cloud, live KMS, same agent, concurrency 32 | TBD | TBD | TBD | TBD | TBD | TBD |

Only commit numbers produced by an actual run. Keep the local results in `BENCHMARKS.md`
separate and label the environment.
