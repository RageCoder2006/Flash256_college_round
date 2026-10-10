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
| Dashboard | Next.js | `dashboard/` (M4) |

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

## Status
M0 done: Go↔pi stdio harness, per-episode simulated world, deterministic oracle, permission/
confused-deputy auditor, hash-chained traces (`agentbreak verify`), seed campaign + benign regression.
