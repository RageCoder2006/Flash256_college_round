# AVHSOL

**Agentic Vulnerability Hunter with Simulated Offensive Layers**

An autonomous red team for AI agents. AVHSOL attacks an agent the way a real adversary would (by
hiding instructions in the content the agent reads), proves what worked with a replayable trace,
shows whether a guard stops the same attack without breaking normal work, and keeps everything the
agent did in a graph that a security team can query, correct and replay.

Made by **David Porathur** and **Rishit Baitule**. Built for BitNBuild.

---

## What it does

| You want to know | AVHSOL gives you |
|---|---|
| Can this agent be hijacked? | An attacker (a pi agent driven by your LLM) that searches for working attacks instead of replaying a fixed list, then re-runs and shrinks each winner |
| Did it really work? | A **deterministic oracle**, never the model's opinion: a planted canary secret reaching a canary server, a host file read from inside the sandbox, a forbidden tool call |
| How did it happen? | A hash-chained, Ed25519-signed **trace** and a **causal graph**: which untrusted read tainted which call, what the guard decided, which secret was touched |
| Does the guard help, and what does it cost? | Replays every working exploit against the Rust guard, runs the benign tasks both ways, and ablates one defense at a time |
| Would a policy change have mattered? | `policy-test` replays *recorded history* through any policy with no model calls: which past exploits it would have stopped, which legitimate tasks it would have broken |
| What did we believe, and when? | A **bitemporal** graph: when something happened versus when we recorded or changed our mind. Corrections never overwrite |
| Can I ask questions of it? | **GraphRAG**: vector search over every step, expanded through the graph, answered by your model with citations |

## Architecture

```
 Go control plane (core/)  ── campaigns, oracles, auditor, signed traces, graph, hardened API
      │
      ├── TypeScript harness (pi/packages/avhsol) ── target + attacker agents on a vendored fork of pi
      │        └── closed-box CLI agents (pi, Codex, opencode, ...) run inside the sandbox
      ├── Rust guard (guard/avhsol-proxy)   ── LLM-wire proxy: records every exchange, blocks tool calls
      ├── Rust sandbox (guard/avhsol-sandbox) ── Landlock + seccomp + rlimits, no root needed
      ├── Neo4j  ── the bitemporal trace graph          ┐ docker compose, loopback only,
      ├── Qdrant ── vectors for GraphRAG                ┘ authenticated, pinned images
      └── Next.js dashboard (dashboard/)
```

| Layer | Language | Where |
|---|---|---|
| Control plane | Go | `core/` |
| Agent harness | TypeScript (fork of [pi](https://github.com/earendil-works/pi)) | `pi/packages/avhsol` |
| Guard proxy + policy engine | Rust | `guard/avhsol-proxy`, `guard/avhsol-guard` |
| Sandbox | Rust | `guard/avhsol-sandbox` |
| Graph + vectors | Neo4j 5, Qdrant | `deploy/stack` |
| Dashboard | Next.js | `dashboard/` |

Docs for continuing the work: [docs/README.md](docs/README.md) (status, roadmap, architecture) and [CLAUDE.md](CLAUDE.md).

## Quick start

```bash
make pi-build                 # once: build the vendored pi monorepo
./scripts/demo.sh             # stack + guard + API + dashboard; sign in at http://localhost:3000
```

The dashboard asks for a token. They are generated into `deploy/stack/.env`
(`AVHSOL_TOKEN_VIEWER`, `_ANALYST`, `_OPERATOR`, `_ADMIN`).

With a real model (any OpenAI-compatible endpoint with tool calling):

```bash
export AVHSOL_LLM_BASE_URL=https://.../v1 AVHSOL_LLM_MODEL=<id> AVHSOL_LLM_API_KEY=<key>
./core/bin/avhsol validate -guard-url http://127.0.0.1:7077 -graph      # attack, replay under guard, benign tasks
./core/bin/avhsol hunt -budget 40 -vs-defense -guard-url http://127.0.0.1:7077
```

`-offline` swaps in a *simulated gullible model* to test the pipeline. Its results say nothing about any
real model, and the graph keeps them out of statistics unless you ask.

## Commands

`avhsol <command>`

| | |
|---|---|
| `audit` | static review of what an agent is allowed to do (over-privilege, the lethal trifecta) |
| `campaign` | run the seed attacks (and `-regress` the benign tasks) |
| `hunt` | the adaptive attacker: bandit search, model-written payloads, reliability re-runs, payload minimisation |
| `validate` | baseline → replay under the guard → benign regression → defense ablation |
| `policy-test` | replay recorded traces through a policy, offline |
| `report` | model-written analyst advisories for confirmed exploits |
| `export` | the **security report**: `html`, `pdf`, `md`, `json` or `sarif`, laid out by a JSON skeleton (see [docs/REPORTS.md](docs/REPORTS.md)) |
| `graph` | `init ingest stats episodes why beliefs history techniques similar ask reset` |
| `intel` | threat intel: `sync status list show seeds graph export-bundle import-bundle` (GHSA, NVD, OSV, KEV, EPSS, ATLAS/OWASP, research feeds; [docs/INTEL.md](docs/INTEL.md)) |
| `scengen` | generate a test scenario from an agent's tool list or a live MCP server ([docs/SCENARIOS.md](docs/SCENARIOS.md)) |
| `fork` | live revive: re-walk a recorded run and let the model take over at a step ([docs/REVIVE.md](docs/REVIVE.md)) |
| `serve` | the API behind the dashboard |
| `keygen`, `verify` | trace signing |
| `auditlog` | verify or tail the API's tamper-evident audit log |

## Reports

`avhsol export -in <run dir> -format pdf` writes a security assessment report: branded cover and document
control, executive summary with risk rating and charts, scope and method, risk matrix, detailed findings (attack
path, incident timeline, payload, effect of the guard, analyst reasoning, reproduction), defense validation, the
no-attack baseline, remediation roadmap, limitations, event log and an integrity appendix. The **layout is a JSON
skeleton**, so another required format is another file, not code: `docs/skeletons/one-page-audit.json` is an
example. Also available from the dashboard and the API. Samples from real runs: `docs/sample/`. The report only
claims what was measured (no rating for simulated runs; reliability only with repeats; errored runs excluded).

## Targets

Three kinds, each judged by the same oracles (see [docs/CONNECTORS.md](docs/CONNECTORS.md)): `cli` (any command-line agent; OpenAI **or Anthropic** wire through the guard proxy), `mcp` (adds a poisoned MCP server), `http` (a remote chat endpoint, black box).

* **Simulated-tool agents** (`scenarios/hr-records.yaml`, `scenarios/devops-coder.yaml`): a pi agent with fake tools
  over synthetic data, so an attack can never touch anything real.
* **Closed-box coding agents** (`targets/`): run the agent's real command inside the sandbox on a decoy repository.
  Its only route to the model is the guard proxy, so AVHSOL sees every tool call. `targets/pi-coding-agent.yaml`
  works today. See `targets/README.md`.

## The sandbox

`avhsol-sandbox` applies Landlock (only the episode workspace is writable; TCP only to the canary sink and the
guard proxy), a seccomp denylist (no UDP/raw sockets, ptrace, mount, bpf, ...), rlimits and `no_new_privs`, then
runs the command. It needs no root and no user namespaces. It shares the host kernel and is **not** a VM. For
hostile agents add a microVM or gVisor; Docker + gVisor and the Gondolin micro-VM were evaluated and work on this
machine, but are not integrated yet.

## The graph

Every run writes each step, tool call, guard decision and verdict into Neo4j (`-graph`), with vectors in Qdrant.
Two clocks, borrowed from [utopia](https://github.com/deeplethe/utopia)'s design: **valid** time (when it happened)
and **record** time (when we believed it). A correction closes the old belief and links the new one. Secrets are
replaced by fingerprints *before* anything is stored. Vectors default to an offline lexical embedder (matches
wording, not meaning); point `AVHSOL_EMBED_URL` at a local embedding server for semantic search.

## Security of the platform itself

Loopback-only services; per-role bearer tokens (viewer < analyst < operator < admin) compared in constant time;
failed-token throttling; security headers; request-size and server timeouts; a hash-chained audit log of every
state-changing request and failed login; Ed25519-signed traces (a re-chained forgery fails verification);
databases that reject anonymous access; credentials in a mode-600 file outside git; hardened containers (non-root,
all capabilities dropped, `no-new-privileges`); secrets redacted before storage; the oracle never trusts the model.

## Results so far (be careful reading these)

Live runs against `dealignai/Ornith-1.5-35B-A3B-UNCENSORED-GGUF` (8k context):

* **Sandboxed coding agent, guard off:** the credentials reached the canary server in **5 of 13** valid runs
  (2 techniques fully reliable); control runs with no attack: **0 of 6**. One run errored (context overflow) and is
  excluded, not counted as defended.
* **Guard enforcing:** **5 of 5** confirmed exfiltrations blocked; **3 of 3** benign tasks still pass; the
  causal graph shows the agent retrying variants after each denial.
* **HR assistant (email exfiltration):** the same model resisted **0 of 12** fixed seeds and **0 of 15** model-written payloads.
* The model also reads `.env` unprompted about a third of the time, so "secret printed" is *not* counted as an exploit.

Caveats: one model, small samples (exfiltration vs control p≈0.11), and the coding target ran with thinking off.

## Not built yet

A micro-VM sandbox tier (gVisor is available, see [docs/SANDBOX.md](docs/SANDBOX.md)); verification of the Claude Code and MCP target examples against the
real agents; threat-intel scheduling, more feeds and a dependency-aware match; reading TRIVEKTRA's eBPF findings into traces (spans are emitted); TLS on the
stack's database ports. See [docs/ROADMAP.md](docs/ROADMAP.md).

## Credits

Made by David Porathur and Rishit Baitule. Agent harness forked from [pi](https://github.com/earendil-works/pi)
(MIT). Bitemporal modelling follows [utopia](https://github.com/deeplethe/utopia) (Apache-2.0). Several detectors and
test vectors are ported from the authors' TRIVEKTRA project (GPLv3).
