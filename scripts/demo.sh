#!/usr/bin/env bash
# Starts the Rust guard, the Go API and the dashboard, then opens http://localhost:3000.
# Set AGENTBREAK_LLM_BASE_URL / AGENTBREAK_LLM_MODEL to use a real model; the Run page's
# "Simulated model" box is on by default and needs no LLM.
set -euo pipefail
cd "$(dirname "$0")/.."
make -s build
(cd guard && cargo build --release -q)
[ -d dashboard/node_modules ] || (cd dashboard && npm install --silent)

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

AGENTBREAK_GUARD_ADDR=127.0.0.1:7077 AGENTBREAK_UPSTREAM="${AGENTBREAK_LLM_BASE_URL:-}" ./guard/target/release/abguard-proxy & pids+=($!)
sleep 1
./core/bin/agentbreak serve -addr 127.0.0.1:8787 -guard-url http://127.0.0.1:7077 ${AGENTBREAK_OFFLINE:+-offline} & pids+=($!)
(cd dashboard && npx next dev -p 3000) & pids+=($!)
echo "dashboard: http://localhost:3000   api: http://127.0.0.1:8787   guard: http://127.0.0.1:7077"
wait
