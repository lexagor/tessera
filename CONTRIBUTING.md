# Contributing

Thanks for helping build the trust plane for autonomous agents.

## Ground rules

1. **Spec before code.** Non-trivial changes start as an RFC in `docs/rfcs/`.
2. **Security is a feature.** Anything touching credentials, policy, or receipts needs a threat-model note.
3. **Keep the SDK a one-liner.** Adoption friction is the enemy.
4. **Tests with every change.** Policy and issuer changes require a red-team case.

## Development

```bash
corepack enable
pnpm install
pnpm build
pnpm typecheck
pnpm test
```

Rust broker:

```bash
cd apps/broker && cargo test
# Postgres-backed tests (chain persistence, partitioning, policy CRUD):
TEST_DATABASE_URL=postgres://user@127.0.0.1:5432/tessera_test cargo test
```

Contracts:

```bash
cd contracts/receipts && forge test -vv
```

## Pull requests

- Conventional commits (`feat:`, `fix:`, `docs:`, `chore:`).
- One logical change per PR.
- Update `docs/` when behavior changes.
- CI must be green (lint, typecheck, test, secret scan).

## Build artifacts & disk usage

Rust debug builds dominate local disk usage. The broker's `target/` directory reached
**~37 GB** (cargo accounted 66 GiB of files) before this policy existed, because macOS's
default `split-debuginfo=unpacked` writes one DWARF-carrying object file per codegen unit
per dependency (~370k `.o` files for this crate's dependency graph), plus per-iteration
incremental caches and 18 stale `libtessera_broker-*.rlib` copies that cargo never
garbage-collects.

`apps/broker/Cargo.toml` therefore sets an artifact-size policy:

```toml
[profile.dev]
debug = "line-tables-only"     # our crate keeps file:line in backtraces

[profile.dev.package."*"]
debug = false                  # dependencies: no DWARF (the bulk of the size)

[profile.dev.build-override]
debug = false                   # build scripts and proc-macros
```

Consequences to know:

- Backtraces still show *our* function names and line numbers; frames inside dependencies
  (tokio, sqlx, …) are symbolized but without source lines. If you need full dependency
  debug info temporarily, change `debug = false` to `debug = 2` under
  `[profile.dev.package."*"]`, reproduce, then revert.
- `incremental` is intentionally left enabled for fast iteration, so `target/debug/incremental`
  will regrow (single-digit GB). Delete just that directory to reclaim it without losing
  compiled dependencies: `rm -rf apps/broker/target/debug/incremental`.
- Full reset (rebuild from the cargo registry cache, no network needed):
  `cd apps/broker && cargo clean`.

A healthy steady state after a rebuild is roughly 5–10 GB. If `du -sh apps/broker/target`
is far above that, something is compiling with full debug info again — check the profiles
have not been overridden (e.g. by `CARGO_PROFILE_DEV_DEBUG=2` in the environment).
