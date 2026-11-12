#!/usr/bin/env bash
#
# Local golden-path run: mock Stripe + anvil (with a deployed ReceiptAnchor) + the broker,
# then the golden-path harness. Everything is torn down on exit.
#
#   ./run-local.sh
#
# Requires: cargo, forge/anvil (Foundry), pnpm (via corepack), and a reachable Postgres
# (defaults to postgres://a@127.0.0.1:5432/tessera_test; override with DATABASE_URL).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"

BROKER_PORT="${BROKER_PORT:-8790}"
MOCK_STRIPE_PORT="${MOCK_STRIPE_PORT:-12111}"
ANVIL_PORT="${ANVIL_PORT:-8547}"
DATABASE_URL="${DATABASE_URL:-postgres://a@127.0.0.1:5432/tessera_test}"
SIGNING_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
ANVIL_PK="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

BROKER_BIN="$ROOT/apps/broker/target/debug/tessera-broker"
LOG_DIR="$(mktemp -d)"

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$LOG_DIR"
}
trap cleanup EXIT INT TERM

echo "==> building broker"
(cd "$ROOT/apps/broker" && cargo build --quiet)

echo "==> starting mock stripe (:$MOCK_STRIPE_PORT)"
node "$ROOT/examples/golden-path/mock-stripe.mjs" >"$LOG_DIR/mock-stripe.log" 2>&1 &
PIDS+=($!)

ANCHOR_ENV=()
if command -v anvil >/dev/null 2>&1 && command -v forge >/dev/null 2>&1; then
  echo "==> starting anvil (:$ANVIL_PORT) + deploying ReceiptAnchor"
  anvil --port "$ANVIL_PORT" --chain-id 1337 --silent >"$LOG_DIR/anvil.log" 2>&1 &
  PIDS+=($!)
  for _ in $(seq 1 50); do
    cast chain-id --rpc-url "http://127.0.0.1:$ANVIL_PORT" >/dev/null 2>&1 && break
    sleep 0.1
  done
  DEPLOY_OUT="$(cd "$ROOT/contracts/receipts" && forge create src/ReceiptAnchor.sol:ReceiptAnchor \
    --rpc-url "http://127.0.0.1:$ANVIL_PORT" --private-key "$ANVIL_PK" --broadcast 2>&1)"
  ANCHOR_ADDR="$(printf '%s' "$DEPLOY_OUT" | grep -oE 'Deployed to: 0x[0-9a-fA-F]{40}' | awk '{print $3}' | head -1)"
  if [[ -n "$ANCHOR_ADDR" ]]; then
    echo "    ReceiptAnchor at $ANCHOR_ADDR"
    ANCHOR_ENV=(
      CHAIN_ID=1337
      RPC_URL="http://127.0.0.1:$ANVIL_PORT"
      ANCHOR_PK="$ANVIL_PK"
      RECEIPT_ANCHOR_ADDRESS="$ANCHOR_ADDR"
    )
  else
    echo "    !! could not deploy ReceiptAnchor; skipping on-chain submit"
  fi
else
  echo "==> anvil/forge not found; skipping on-chain anchoring"
fi

echo "==> starting broker (:$BROKER_PORT)"
(
  export BROKER_PORT="$BROKER_PORT"
  export BROKER_SIGNING_KEY="$SIGNING_KEY"
  export TESSERA_DEMO_ALLOW=1
  export TESSERA_DEMO_KEY=tsk_demo_local
  export DATABASE_URL="$DATABASE_URL"
  export STRIPE_RESTRICTED_KEYS="charges_create=rk_test_local,refunds_create=rk_test_local"
  export STRIPE_API_BASE="http://127.0.0.1:$MOCK_STRIPE_PORT"
  if [[ ${#ANCHOR_ENV[@]} -gt 0 ]]; then export "${ANCHOR_ENV[@]}"; fi
  exec "$BROKER_BIN"
) >"$LOG_DIR/broker.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 80); do
  curl -sf "http://127.0.0.1:$BROKER_PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.15
done
if ! curl -sf "http://127.0.0.1:$BROKER_PORT/healthz" >/dev/null 2>&1; then
  echo "!! broker failed to start; log:"; cat "$LOG_DIR/broker.log"; exit 1
fi

echo "==> running golden path"
TESSERA_ENDPOINT="http://127.0.0.1:$BROKER_PORT" \
TESSERA_API_KEY="tsk_demo_local" \
  corepack pnpm --filter @tessera/golden-path start
