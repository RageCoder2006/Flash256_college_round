# AVHSOL — project guide for agents

**AVHSOL** (Agentic Vulnerability Hunter with Simulated Offensive Layers) is an autonomous red team for AI agents.
Made by David Porathur and Rishit Baitule. Read `docs/README.md` first for the full handover; this file is the short version.

## What it does
Attacks a target agent (hidden instructions in content it reads) → a deterministic oracle decides if it worked → signed, hash-chained
trace → replay under the Rust guard → benign-task regression → defense ablation → report. Everything lands in a bitemporal Neo4j graph
(+ Qdrant vectors) that is queryable (GraphRAG) and shown as a 3D "neural graph" in the dashboard.

## Layout
| Path | What |
|---|---|
| `core/` | Go 1.22 control plane. `cmd/avhsol` (CLI), `internal/{campaign,attacker,oracle,audit,trace,sign,graph,api,export,...}` |
| `guard/` | Rust: `avhsol-guard` (policy), `avhsol-proxy` (LLM-wire proxy), `avhsol-sandbox` (Landlock+seccomp) |
| `pi/` | Vendored fork of pi; our harness is `pi/packages/avhsol` (TypeScript) |
| `dashboard/` | Next.js 16 / React 19. `/` landing, `/console/*` app. `lib/graph3d.ts`, `components/graph3d/NeuralGraph.tsx` |
| `core/internal/{home,whitebox,tools,mcpserver,runtime}` | install-aware paths; `avhsol .` code audit; the tool registry shown in Settings and served over MCP; guard-proxy lifecycle |
| `scenarios/`, `seeds/`, `targets/` | Target definitions, attack seeds, closed-box CLI agent specs |
| `deploy/stack/` | docker compose for Neo4j + Qdrant; `.env` (mode 600, gitignored) holds DB creds and API tokens |
| `core/internal/{sysmon,eval,tui}` | host/sandbox monitoring, the shared security evaluation, the Bubble Tea terminal UI |
| `docs/` | Handover docs: STATUS, ROADMAP, INTEL, CONNECTORS, SANDBOX, REVIVE, SCENARIOS, REPORTS, plus the approved plan |

## Commands
```
make build              # Go binary -> core/bin/avhsol
make test               # cargo test + go test ./... + vitest
make pi-build           # once
make install            # user-level install to ~/.local (scripts/install.sh); then: avhsol .   /   claude mcp add avhsol -- avhsol mcp
./scripts/demo.sh       # stack + guard + API + dashboard (AVHSOL_OFFLINE=1 for the simulated model)
cd dashboard && npx tsc --noEmit && npx next build
cd core && go test ./...     # graph integration tests need the live Neo4j/Qdrant stack; the gVisor test needs docker+runsc and core/bin/avhsol
avhsol intel sync            # fetch threat intel (the only network command); avhsol intel -h for the rest
avhsol scengen -tools t.json # scenario from a tool list; avhsol fork -trace ID -at N   # live revive
```

## Rules (do not break)
* **Never commit unless the user asks.** Never put the LLM key or any token in a file, memory or log. The model is configured only via
  `AVHSOL_LLM_BASE_URL`, `AVHSOL_LLM_MODEL`, `AVHSOL_LLM_API_KEY`.
* **Be honest about results.** Oracles decide success, never the model. Simulated (`-offline`) runs are labelled and excluded from stats.
  Errored runs are excluded from ASR. No risk rating without ≥3 repeats.
* Secrets are redacted to fingerprints before storage. Attacker-controlled text is always escaped when rendered.
* Services bind loopback only. State-changing API requests are audited. Keep roles viewer < analyst < operator < admin.
* Match surrounding style; keep Go formatted (`gofmt`) and `go vet` clean. Go is 1.22.2: `golang.org/x/net` is pinned to v0.28.0.

* Threat-intel text is third-party data: never feed it to a model unquoted, never let it change a risk rating. Intel-derived seeds carry `ref`; they are ideas, not findings.
* Only `avhsol intel sync` (and the admin `POST /api/intel/sync`) may use the network for intel; nothing fetches during a run.

* **Never run test campaigns into a real run directory** (`out-coding-live`, `out-intel-live`): they mix simulated traces into real results and overwrite `report.json`. Use a scratch `-out`.
* The TUI libraries are pinned for Go 1.22 (bubbletea v1.1.0, lipgloss v1.0.0, bubbles v0.20.0); do not let `go get -u` raise them.
* A multi-stage scenario's `followup_task` runs in a fresh agent session; `World.NewSession` clears context taint but keeps memory.

* Never hard-code `scenarios/`, `seeds/`, `guard/target/...` or `deploy/stack/...`: use `internal/home` (`Assets`, `Resolve`, `Bin`, `SigningKey`, `StateDir`). `avhsol .` writes runs outside the audited directory and never executes the audited code except in the sandbox.

## Gotchas
* Reasoning model: send `chat_template_kwargs.enable_thinking=false` for attacker/analyst/ask calls. Context is 8192 tokens.
* Don't `pkill -f` a pattern that matches your own shell; kill by port.
* After moving Next routes delete `dashboard/.next` (stale generated types).
* The API must be restarted after rebuilding the Go binary. Activation/overview endpoints: `/api/graph/overview`, `/api/graph/activate`, `/api/graph/ask`.
* WebGL in headless Chrome needs `--use-angle=swiftshader --enable-unsafe-swiftshader --ignore-gpu-blocklist`.
