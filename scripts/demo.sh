#!/usr/bin/env bash
# AVHSOL (Agentic Vulnerability Hunter with Simulated Offensive Layers)
# Starts everything: Neo4j + Qdrant, the Rust guard, the Go API and the dashboard.
#
#   ./scripts/demo.sh                       # simulated model, hr-records scenario
#   SCENARIO=scenarios/devops-coder.yaml SEEDS=seeds/coding-seeds.yaml ./scripts/demo.sh
#   AVHSOL_LLM_BASE_URL=... AVHSOL_LLM_MODEL=... AVHSOL_LLM_API_KEY=... ./scripts/demo.sh   # real model
set -euo pipefail
cd "$(dirname "$0")/.."

make -s build
(cd guard && cargo build --release -q)        # avhsol-proxy + avhsol-sandbox
[ -d dashboard/node_modules ] || (cd dashboard && npm install --silent)
./scripts/stack.sh up                          # Neo4j + Qdrant (generates credentials and API tokens on first run)
[ -f deploy/stack/signing.key ] || ./core/bin/avhsol keygen
./core/bin/avhsol graph init >/dev/null

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

AVHSOL_GUARD_ADDR=127.0.0.1:7077 AVHSOL_UPSTREAM="${AVHSOL_LLM_BASE_URL:-}" ./guard/target/release/avhsol-proxy & pids+=($!)
sleep 1
./core/bin/avhsol serve -graph -addr 127.0.0.1:8787 -guard-url http://127.0.0.1:7077 \
  -scenario "${SCENARIO:-scenarios/hr-records.yaml}" -seeds "${SEEDS:-seeds/seeds.yaml}" ${AVHSOL_OFFLINE:+-offline} & pids+=($!)
(cd dashboard && npx next dev -p 3000) & pids+=($!)

echo
echo "AVHSOL is up:  dashboard http://localhost:3000   API http://127.0.0.1:8787   Neo4j browser http://127.0.0.1:7474"
echo "Sign in with a token from deploy/stack/.env (AVHSOL_TOKEN_VIEWER / ANALYST / OPERATOR / ADMIN)."
wait
