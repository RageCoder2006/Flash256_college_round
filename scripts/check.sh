#!/usr/bin/env bash
# One command that runs every automated check: Go (format, vet, tests), Rust, the TypeScript harness, and the dashboard types.
# Graph integration tests skip themselves when Neo4j is not up; the gVisor test skips without docker+runsc.
set -euo pipefail
cd "$(dirname "$0")/.."
echo "== go";   (cd core && test -z "$(gofmt -l .)" || { gofmt -l .; echo "gofmt needed"; exit 1; }; go vet ./... && go build -o bin/avhsol ./cmd/avhsol && go test ./...)
echo "== rust"; (cd guard && cargo test -q)
echo "== ts";   (cd pi/packages/avhsol && npx tsc --noEmit -p tsconfig.build.json && npx vitest --run)
echo "== dashboard"; (cd dashboard && npx tsc --noEmit)
echo "all checks passed"
