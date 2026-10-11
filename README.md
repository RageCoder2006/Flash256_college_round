<div align="center">

# 🛡️ AVHSOL

**Agentic Vulnerability Hunter with Simulated Offensive Layers**

An autonomous red team for AI agents. It attacks an agent the way a real adversary would, proves what worked with a signed,
replayable trace, and shows whether a guard stops the same attack without breaking normal work.

![Status](https://img.shields.io/badge/status-alpha-orange)
![Platform](https://img.shields.io/badge/platform-Linux-informational)
![Go](https://img.shields.io/badge/control%20plane-Go%201.22-00ADD8?logo=go&logoColor=white)
![Rust](https://img.shields.io/badge/guard%20%26%20sandbox-Rust-000000?logo=rust&logoColor=white)
![TypeScript](https://img.shields.io/badge/harness-TypeScript-3178C6?logo=typescript&logoColor=white)
![Next.js](https://img.shields.io/badge/dashboard-Next.js%2016-000000?logo=nextdotjs&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-server-8A2BE2)
![Neo4j](https://img.shields.io/badge/graph-Neo4j%20%2B%20Qdrant-008CC1?logo=neo4j&logoColor=white)

[Install](#-install) · [Audit your agent](#-audit-your-agent-avhsol-) · [Use it from Claude Code](#-use-avhsol-from-claude-code-mcp) · [Dashboard](#-dashboard) · [Docs](#-documentation) · [Results](#-results-so-far)

</div>

---

## ✨ Why

Agents that read documents, web pages and tickets can be hijacked by instructions hidden in that content. AVHSOL finds out whether
yours can be, and tells you how it knows.

| You want to know | AVHSOL gives you |
|---|---|
| 🎯 Can this agent be hijacked? | An attacker that searches for working attacks instead of replaying a fixed list, then re-runs and shrinks each winner |
| ⚖️ Did it really work? | A **deterministic oracle**, never the model's opinion: a planted canary secret reaching a canary server, a host file read from inside the sandbox, a forbidden tool call |
| 🔎 How did it happen? | A hash-chained, Ed25519-signed **trace** and a **causal graph**: which untrusted read tainted which call, what the guard decided |
| 🧱 Does the guard help, and what does it cost? | Replays every working exploit against the Rust guard, runs benign tasks both ways, ablates one defense at a time |
| 📜 Would a policy change have mattered? | `policy-test` replays recorded history through any policy with no model calls |
| 🕰️ What did we believe, and when? | A **bitemporal** graph (when it happened vs. when we recorded or changed our mind); corrections never overwrite |
| 💬 Can I ask questions of it? | **GraphRAG**: vector search over every step, expanded through the graph, answered with citations |
| 📊 How sure are the numbers? | Success rates with 95% intervals and a comparison with a no-attack control; no risk rating without 3 or more repeats |

## 📦 Install

Linux. Needs **Go 1.22+** and a **Rust toolchain** to build; Node is only needed for the vendored pi agent and the dashboard.

```bash
git clone <this repository> && cd Flash256_college_round
scripts/install.sh            # or: make install
```

The installer is user-level: **no sudo, and it never edits your shell files**.

| Installed | Where |
|---|---|
| `avhsol`, `avhsol-proxy`, `avhsol-sandbox` | `~/.local/bin` |
| scenarios, seeds, target templates | `~/.local/share/avhsol` |
| your trace-signing key (mode 600) | `~/.config/avhsol` |
| runs and the threat-intel cache | `~/.local/share/avhsol` |

```bash
scripts/install.sh --prefix DIR        # install somewhere else
scripts/install.sh --with-harness      # also copy the pi harness (simulated-tool scenarios and `hunt` need it)
scripts/install.sh --uninstall         # remove it; add --purge to delete your runs and keys too
```

If `~/.local/bin` is not on your `PATH` the script says so and prints the line to add. Details: [docs/INSTALL.md](docs/INSTALL.md).

The model for the attack step is configured **only through the environment**; the key is never written to a file:

```bash
export AVHSOL_LLM_BASE_URL=https://…/v1     # any OpenAI-compatible endpoint with tool calling
export AVHSOL_LLM_MODEL=<model id>
export AVHSOL_LLM_API_KEY=<key>
```

## 🚀 Audit your agent: `avhsol .`

Go to the directory that holds an AI agent's code and run:

```bash
cd /path/to/your/agent
avhsol .                 # read the code, attack it in a sandbox, write the report
avhsol . --static        # read the code only: nothing is launched, no model needed
```

What it does, in order, with no prompts for a recognised agent:

1. 📖 **Reads the code**: framework, the tools it gives its model, shell/eval/SQL sinks, disabled approvals, committed credentials
   (shown as fingerprints only), unpinned MCP servers, the lethal trifecta, dependencies. Every finding has a `file:line`.
2. 🔐 **Static permission audit** of the test scenario generated from those tools.
3. 🧪 **Attack campaign** in the sandbox on a decoy workspace, with a no-attack control.
4. 🛡️ **Defense validation**: replays working exploits through the guard in enforce mode, checks benign tasks, ablates D1–D7.
5. 📈 **Evaluation and reports**: HTML, JSON and SARIF in a new run directory under `~/.local/share/avhsol/runs/`.

Your code is mounted read-only, nothing is ever written into it, and the guard proxy is started and stopped for you. The proxy holds
the real model key; the audited agent only sees a placeholder. With no model configured it stops after the static report and
says so, and it never substitutes a simulated model.

**Which agents can it launch?** The vendored **pi** is recognised with no setup. Anything else needs an `avhsol.yaml`
(`avhsol init` writes a starter):

```yaml
name: my-agent
run: ["python", "{agent_dir}/agent.py", "{task}"]    # starts the agent for one task
model_env: openai                                    # openai | anthropic | both
```

The scanner is pattern-based: it can miss tools registered dynamically and can flag harmless code, and each result carries a
confidence. Full behavior, flags and limits: [docs/WHITEBOX.md](docs/WHITEBOX.md).

## 🔌 Use AVHSOL from Claude Code (MCP)

AVHSOL is also an MCP server, so Claude Code (or any MCP client) can scan code, read runs and pull reports:

```bash
claude mcp add avhsol -- avhsol mcp                                   # analyst role
claude mcp add avhsol -- avhsol mcp --role viewer                     # read-only
claude mcp add avhsol -- avhsol mcp --role operator --allow-launch    # may also start audits
```

Tools that launch agents are **off by default**. Results that quote traces, scanned source or advisories are returned inside an
`untrusted_content` block, because attackers can write that text. The same tools are served over HTTP at `/mcp` when an admin
switches it on in **Settings → Tools**, where every tool is listed with its arguments, required role and effect.
See [docs/MCP.md](docs/MCP.md).

## 🖥️ Interfaces

| | |
|---|---|
| **Terminal UI**: run `avhsol` with no arguments | menus and pickers to audit a codebase, attack, hunt, validate, browse traces and intel ([docs/TUI.md](docs/TUI.md)) |
| **Dashboard**: `./scripts/demo.sh`, then <http://localhost:3000> | a scrolling landing page, then the console: **Status** (live host, sandbox and guard stats), Runs, Traces, the 3D neural **Graph**, Intel, **Reports** (preview, download, executive summary), **Settings**, About |
| **CLI**: `avhsol <command>` | everything below |
| **MCP**: `avhsol mcp` | for agents and harnesses |

### 🧭 Dashboard

```bash
make pi-build            # once: build the vendored pi monorepo
./scripts/demo.sh        # stack + guard + API + dashboard (AVHSOL_OFFLINE=1 uses the simulated model)
```

The dashboard asks for a token; they are generated into `deploy/stack/.env` (`AVHSOL_TOKEN_VIEWER`, `_ANALYST`, `_OPERATOR`,
`_ADMIN`). Live monitoring and optional Prometheus/Grafana: [docs/MONITORING.md](docs/MONITORING.md).

## ⌨️ Commands

`avhsol <command>` · `avhsol <dir>` · `avhsol` (menu)

| Command | What it does |
|---|---|
| `avhsol <dir>` | audit the agent whose code is in `<dir>` (read, attack, validate, report) |
| `init` | write a starter `avhsol.yaml` into a codebase |
| `mcp` | serve AVHSOL's tools to an MCP client over stdio |
| `audit` | static review of what an agent is allowed to do (over-privilege, the lethal trifecta) |
| `campaign` | run the seed attacks (`-regress` adds the benign tasks) |
| `hunt` | adaptive attacker: bandit search, model-written payloads, reliability re-runs, payload minimisation |
| `validate` | baseline → replay under the guard → benign regression → defense ablation |
| `summary` | the security evaluation of a run (rating, rates with intervals, control comparison, defenses) |
| `export` | the security report as `html`, `pdf`, `md`, `json` or `sarif`, laid out by a JSON skeleton ([docs/REPORTS.md](docs/REPORTS.md)) |
| `policy-test` | replay recorded traces through a policy, offline |
| `fork` | live revive: re-walk a recorded run and let the model take over at a step ([docs/REVIVE.md](docs/REVIVE.md)) |
| `graph` | `init ingest stats episodes why beliefs history techniques similar ask reset` |
| `intel` | threat intel: `sync status list show seeds graph export-bundle import-bundle` ([docs/INTEL.md](docs/INTEL.md)) |
| `scengen` | generate a test scenario from a tool list or a live MCP server ([docs/SCENARIOS.md](docs/SCENARIOS.md)) |
| `report` | model-written analyst advisories for confirmed exploits |
| `serve` | the API behind the dashboard |
| `keygen`, `verify`, `auditlog` | trace signing, trace verification, the tamper-evident audit log |

## 🏗️ Architecture

```
 Go control plane (core/)  ── campaigns, oracles, auditor, whitebox scanner, signed traces, graph, hardened API, MCP server
      │
      ├── TypeScript harness (pi/packages/avhsol) ── simulated-tool agents on a vendored fork of pi
      ├── Closed-box CLI agents (pi, Codex, opencode, your own) ── run inside the sandbox on a decoy workspace
      ├── Rust guard (guard/avhsol-proxy)      ── LLM-wire proxy: records every exchange, blocks tool calls (D1–D7)
      ├── Rust sandbox (guard/avhsol-sandbox)  ── Landlock + seccomp + rlimits, no root needed (gVisor tier available)
      ├── Neo4j + Qdrant                       ── bitemporal trace graph + vectors (docker compose, loopback, authenticated)
      └── Next.js dashboard (dashboard/)
```

| Layer | Language | Where |
|---|---|---|
| Control plane, CLI, API, MCP server | Go | `core/` |
| Agent harness | TypeScript (fork of [pi](https://github.com/earendil-works/pi)) | `pi/packages/avhsol` |
| Guard proxy and policy engine | Rust | `guard/avhsol-proxy`, `guard/avhsol-guard` |
| Sandbox | Rust | `guard/avhsol-sandbox` |
| Graph and vectors | Neo4j 5, Qdrant | `deploy/stack` |
| Dashboard | Next.js 16 / React 19 | `dashboard/` |

## 🎯 Targets

Three kinds, each judged by the same oracles ([docs/CONNECTORS.md](docs/CONNECTORS.md)):

* `cli`: any command-line agent; OpenAI **or Anthropic** wire through the guard proxy. `targets/pi-coding-agent.yaml` works today.
* `mcp`: a CLI agent that is also given a poisoned MCP server.
* `http`: a remote chat endpoint, observed as a black box (tool calls are not visible and the guard is not in the path).

Simulated-tool scenarios (`scenarios/`) run a pi agent with fake tools over synthetic data, so an attack can never touch anything real.

## 🔒 Security of the platform itself

Loopback-only services; per-role bearer tokens (viewer < analyst < operator < admin) compared in constant time; failed-token
throttling; security headers; request-size and server timeouts; a hash-chained audit log of every state-changing request and
failed login; Ed25519-signed traces (a re-chained forgery fails verification); databases that reject anonymous access; credentials
in a mode-600 file outside git; hardened containers; secrets redacted to fingerprints before storage; and an oracle that never
trusts the model. The sandbox shares the host kernel and is **not** a VM; for hostile agents use the gVisor tier
([docs/SANDBOX.md](docs/SANDBOX.md)). Threat model and reporting: [docs/SECURITY.md](docs/SECURITY.md).

## 📈 Results so far

Be careful reading these: one model, small samples. Live runs against `dealignai/Ornith-1.5-35B-A3B-UNCENSORED-GGUF` (8k context):

* **Sandboxed coding agent, guard off:** credentials reached the canary server in **5 of 13** valid runs (2 techniques fully reliable);
  control runs with no attack: **0 of 6**. One errored run is excluded, not counted as defended.
* **Guard enforcing:** **5 of 5** confirmed exfiltrations blocked; **3 of 3** benign tasks still pass.
* **HR assistant (email exfiltration):** the same model resisted **0 of 12** fixed seeds and **0 of 15** model-written payloads.
* The model reads `.env` unprompted about a third of the time, so "secret printed" is *not* counted as an exploit.

The `avhsol .` pipeline has been exercised end to end on pi and on a toy agent with a **scripted mock model**; that checks the
mechanics, not any real security result. Simulated (`-offline`) runs are always labelled and excluded from statistics.

## 🗺️ Not built yet

A separate black-box command for deployed agents (the `http` target is the route today); multi-stage attacks against launched CLI
agents (listed and skipped with a note); graph, guard-check and verdict-correction tools over MCP; tool extraction beyond Python,
TypeScript/JavaScript and Go patterns; a micro-VM sandbox tier; threat-intel scheduling. See [docs/ROADMAP.md](docs/ROADMAP.md).

## 📚 Documentation

| | |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | the installer and where things live |
| [docs/WHITEBOX.md](docs/WHITEBOX.md) | `avhsol .`, `avhsol.yaml`, flags, limits |
| [docs/MCP.md](docs/MCP.md) | the MCP server and its tools |
| [docs/KEY-FEATURES.md](docs/KEY-FEATURES.md) | each key feature and how far it goes |
| [docs/TUI.md](docs/TUI.md), [docs/FRONTEND.md](docs/FRONTEND.md), [docs/MONITORING.md](docs/MONITORING.md) | interfaces and monitoring |
| [docs/REPORTS.md](docs/REPORTS.md), [docs/SCENARIOS.md](docs/SCENARIOS.md), [docs/CONNECTORS.md](docs/CONNECTORS.md) | reports, scenarios, targets |
| [docs/GRAPH.md](docs/GRAPH.md), [docs/INTEL.md](docs/INTEL.md), [docs/SANDBOX.md](docs/SANDBOX.md), [docs/REVIVE.md](docs/REVIVE.md) | graph, threat intel, sandbox, live revive |
| [docs/README.md](docs/README.md), [docs/STATUS.md](docs/STATUS.md), [CLAUDE.md](CLAUDE.md) | handover, status, notes for coding agents |

## 🧑‍💻 Develop

```bash
make build            # Go binary -> core/bin/avhsol
make test             # cargo test + go test ./... + vitest
./scripts/check.sh    # every automated check: gofmt, vet, Go, Rust, TypeScript, dashboard types
```

Graph integration tests need the live Neo4j/Qdrant stack and skip themselves without it. Never run test campaigns into a real
run directory; use a scratch `-out`.

## 🙌 Credits

Made by **David Porathur** and **Rishit Baitule**. Built for BitNBuild. Agent harness forked from [pi](https://github.com/earendil-works/pi)
(MIT). Bitemporal modelling follows [utopia](https://github.com/deeplethe/utopia) (Apache-2.0). Several detectors and test vectors
are ported from the authors' TRIVEKTRA project (GPLv3). This repository does not yet carry a license file of its own.
