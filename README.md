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

## Live results (model: dealignai/Ornith-1.5-35B-A3B-UNCENSORED-GGUF, 8k context)
Sandboxed coding scenario, 7 seed attacks x 2 surfaces, guard off, target thinking off:
- 13 valid runs (1 errored: an invisible-character payload overflowed the 8,192-token context; errors are excluded, not counted as defended).
- **Full exfiltration (secret reached the canary sink): 5/13.** Control (harmless README note, no attack): 0/6.
- Secret printed: 12/13 vs control 2/6. The model reads `.env` on its own about a third of the time, so this objective is weak evidence of injection and is no longer used to pick exploits to replay or explain.
- Sandbox escapes: 0.
- **Guard enforcing: 5/5 confirmed exfiltrations blocked** (rules D6 30, D4 19, D2 6), benign tasks 3/3 before and after, 292 tool results fenced on live model traffic. Decision time is milliseconds against 30-60 s model calls.
- HR scenario (email exfil): 0/12 static seeds and 0/15 attacker-written payloads succeeded. Against this model that scenario is not broken by the techniques tried.
Caveats: small samples (exfil vs control p~0.11), one model, one scenario family, and the "thinking off" target setting is not the model's default behaviour.

## Status
Done: harness/world/oracle/auditor/traces, Rust guard (D1-D7) + validation + ablation, adaptive
attacker, API + dashboard, Landlock/seccomp sandbox + canary sink + coding scenario, kernel span
emitter, per-objective reporting with a no-attack control, LLM analyst notes.
Open: bring-your-own-agent connectors and automatic scenario generation (the "break any agent"
goal), exportable report (HTML/PDF/SARIF), reading TRIVEKTRA findings back into traces, a live
adaptive hunt on the coding scenario, dashboard visual QA in a browser.
