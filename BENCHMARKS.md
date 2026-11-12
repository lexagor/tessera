# Benchmarks

These are measured numbers, not aspirational targets. They are intentionally split into
in-memory and Postgres runs so broker overhead is not confused with database or provider
latency.

## Environment

| | |
|---|---|
| Machine | Apple M5, 16 GB RAM |
| OS | macOS 27.2 |
| Rust | 1.98.1 |
| Node | 22.23.4 |
| Broker baseline | `5d91c6f2` + benchmark harness |
| Issuer | mock Stripe issuer, no live provider calls |

## Commands

```bash
# Rust microbenchmarks
cd apps/broker
cargo bench --bench crypto -- --noplot

# HTTP authorize latency (broker running with demo mode + mock issuer)
BENCH_REQUESTS=200 BENCH_CONCURRENCY=4 pnpm bench:http

# Offline verification (published verifier package)
pnpm bench:verify
```

For the Postgres HTTP run, start the broker with `DATABASE_URL` pointed at a disposable
database and set `TESSERA_ENDPOINT=http://127.0.0.1:<port>`.

## Microbenchmarks

| Benchmark | Result |
|---|---:|
| Policy evaluation (constraint + CEL) | 4.47 µs |
| Canonical JSON + Keccak hash | 1.28 µs |
| Receipt payload hash | 5.29 µs |
| EIP-712 receipt signing | 32.87 µs |

## HTTP authorize latency

**In-memory broker, mock issuer, 200 requests, concurrency 4:**

| Metric | Result |
|---|---:|
| Throughput | 908 req/s |
| Mean | 4.37 ms |
| p50 | 4.05 ms |
| p95 | 6.04 ms |
| p99 | 14.83 ms |

**Postgres broker, mock issuer, 200 requests, concurrency 4:**

| Metric | Result |
|---|---:|
| Throughput | 422 req/s |
| Mean | 9.43 ms |
| p50 | 7.36 ms |
| p95 | 21.26 ms |
| p99 | 30.82 ms |

These runs include the HTTP client (Node `fetch`) and loopback overhead, so they are
end-to-end client-observed numbers, not pure server-side timings.

## Offline verification

Fixture: signed v2 receipt from `packages/receipt-schema/fixtures/receipt-v2-signed.json`.

| Metric | Result |
|---|---:|
| Receipt size | 2,243 bytes |
| Iterations | 10,000 |
| Mean | 0.964 ms |
| p50 | 0.956 ms |
| p95 | 1.023 ms |
| p99 | 1.055 ms |

Verification uses the published `@tessera-verify/verify` code path and makes no network call.

## Caveats

- The mock issuer removes provider latency; real Stripe/AWS/GitHub latency is additive.
- The Postgres run uses a disposable local database and local loopback.
- These numbers are for regression tracking and diligence conversations, not a production SLA.
- Re-run on the target hardware before quoting numbers externally.
