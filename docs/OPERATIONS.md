# Operations

```
make pi-build && ./scripts/demo.sh          # sign in at http://localhost:3000 with a token from deploy/stack/.env
export AVHSOL_LLM_BASE_URL=... AVHSOL_LLM_MODEL=... AVHSOL_LLM_API_KEY=...   # real model; never write these to a file
./core/bin/avhsol validate -guard-url http://127.0.0.1:7077 -graph
./core/bin/avhsol hunt -budget 40 -vs-defense -guard-url http://127.0.0.1:7077
```
Tests: `make test`; dashboard `npx tsc --noEmit`, `npx next build`.
Ports: guard 7077, API 8787, dashboard 3000, Neo4j 7474/7687, Qdrant 6333 (loopback).
Troubleshooting: sign-in lockout = too many wrong tokens (restart API to clear); `/api/graph/ask` returns 503 without LLM + vector store configured;
stale `.next` types after moving routes → `rm -rf dashboard/.next`; headless WebGL flags are in CLAUDE.md.
