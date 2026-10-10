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

## Scenarios
| Scenario | Target | Attack surface | What it shows |
|---|---|---|---|
| `scenarios/hr-records.yaml` | HR assistant (read docs, search records, send email) | resumes | EchoLeak-style data exfiltration by email |
| `scenarios/devops-coder.yaml` | coding agent with `bash` in a **real sandbox** | README / CONTRIBUTING | poisoned setup steps leaking `.env`, plus a host-file escape probe |

Run the coding scenario: `agentbreak validate -offline -guard-url http://127.0.0.1:7077 -scenario scenarios/devops-coder.yaml -seeds seeds/coding-seeds.yaml -out out-coding`.

## Sandbox (`guard/absandbox`)
No root and no user namespaces needed (many distros block them). It applies Landlock (filesystem:
only the episode workspace is writable; TCP connect: only the canary sink port), a seccomp
denylist (ptrace, mount, bpf, UDP/raw sockets, ...), rlimits and no_new_privs, then `exec`s the
command. A host-only secret outside the workspace and the canary sink are the escape oracle: if the
secret shows up in output or changes, or the sink receives workspace data, it is logged as a finding.
`bash` never runs without it.

## TRIVEKTRA bridge
`-kernel-otlp http://127.0.0.1:<port>` emits an OTLP `execute_tool` span per sandboxed command with
the sandbox's real PID (`process.pid`), in the format TRIVEKTRA's `genaispan` receiver accepts, so
its eBPF agent can tie each tool call to kernel process/file/network events. Needs TRIVEKTRA's
agent running (root, eBPF). The emitter is unit-tested; the live round trip is not exercised here.

## Status
Done: harness/world/oracle/auditor/traces, Rust guard (D1-D7) + validation + ablation, adaptive
attacker, API + dashboard, Landlock/seccomp sandbox + canary sink + coding scenario, kernel span
emitter. Open: reading TRIVEKTRA's findings back into traces; a live-LLM run (waiting on the model URL).
