# AgentBreak: the autonomous AI red team
BitNBuild

AgentBreak probes AI agents for exploitable vulnerabilities (instructions, memory, retrieved
content, tool permissions, multi-step execution), records reproducible attack traces, and
measures whether a toggleable guard stops the same attacks without breaking benign tasks.

| Layer | Language | Where |
|---|---|---|
| Control plane: campaigns, oracles, auditor, traces | Go | `core/` |
| Agent harness (target + attacker agents) | TypeScript, forked from [pi](https://github.com/earendil-works/pi) | `pi/packages/agentbreak` |
| Guard proxy + sandbox | Rust | `guard/` (M1+) |
| Dashboard | Next.js | `dashboard/` |

`pi/` is a vendored fork (upstream commit in `pi/UPSTREAM_COMMIT`); AgentBreak's changes live in
`pi/packages/agentbreak` and are kept out of pi's own packages where possible.

## Quick start (no LLM needed)
```
make pi-build        # one-time: installs and builds the pi monorepo
make demo-offline    # simulated gullible model; validates the pipeline end to end
```
With a real model (OpenAI-compatible `/v1` endpoint, e.g. Unsloth):
```
export AGENTBREAK_LLM_BASE_URL=http://127.0.0.1:8888/v1 AGENTBREAK_LLM_MODEL=<model-id>
./core/bin/agentbreak campaign -regress
```
`-offline` results are **not** a measurement of any real model.

## Dashboard
`make demo` starts the Rust guard (:7077), the Go API (:8787) and the dashboard (:3000). Open
http://localhost:3000, go to **Run**, start a validation, then read the **Verdict** page: each
exploit is drawn as a breach line (red end to end with the guard off; cut at the blocked call,
with the rule id, with the guard on).

## Commands
`agentbreak audit | campaign | validate | hunt | serve | verify`. `hunt` is the autonomous attacker
(UCB1 bandit over technique × surface × operator, LLM-written payloads via the pi AttackerAgent,
reliability re-runs, payload minimisation, optional `-vs-defense`).

## Status
Done: M0 harness/world/oracle/auditor/traces, M1 Rust guard + validation + ablation, M2 adaptive
attacker, M4 API + dashboard. Open: M3 Rust sandbox + coding-agent scenario, M5 TRIVEKTRA eBPF bridge.
