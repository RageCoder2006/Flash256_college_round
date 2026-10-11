# Status

The seven key features and how far each goes: [KEY-FEATURES.md](KEY-FEATURES.md).

## Implemented

**Testing pipeline** — attack seeds and an adaptive hunter (bandit, model-written payloads, reliability re-runs, minimisation); deterministic oracles and a canary
sink; Rust guard (D1–D7) and proxy; guard replay, benign regression, defense ablation, offline `policy-test`; hash-chained Ed25519-signed traces with secrets
redacted to fingerprints; report engine (HTML/PDF/MD/JSON/SARIF) driven by JSON skeletons.

**Graph** — bitemporal Neo4j graph + Qdrant vectors, GraphRAG with citations, spreading activation, per-step LLM/rule narration for replays, hardened role-based API
with a hash-chained audit log.

**Dashboard** — threat-intel page (data sources, search, knowledge graph); dark redesign, landing page with a full architecture diagram, console, 3D neural graph with command-centre replay, node inspector, chat dock,
hideable sidebar. (Frozen during the latest round.)

**Latest round (see [PLAN-intel-and-core.md](PLAN-intel-and-core.md))**

| Phase | Built | Verified |
|---|---|---|
| A. Threat intel | GHSA, NVD, OSV, KEV, EPSS, arXiv feeds, ATLAS/OWASP taxonomy, signed offline bundles, seed generation, Intel graph nodes, report enrichment, API | parser tests on fixtures; **live sync** of all sources (973 items, KEV and EPSS enrichment); live Neo4j test; report export with real cache |
| B. Connectors | Anthropic `/v1/messages` in the proxy; `http` targets (black box); `mcp` targets with a poisoned MCP server | Rust unit tests + mock-upstream round trip; HTTP target end to end (71% vs gullible, 0% vs safe); MCP protocol tests |
| C. Scenario generation | `avhsol scengen` (rules + optional model assist, lint) | unit tests; generated scenario ran a campaign; live MCP tool listing |
| D. Sandbox | `gvisor` backend, stdio port tunnel (`netmux`) | live container test; identical oracle results to Landlock (10/14 both) |
| E. Live revive | `avhsol fork`: harness history + closed-box cassette, edits, API, `FORKED_FROM` | harness vitest; end to end with a mock OpenAI-compatible model on both paths |

## Live results with the real model (Ornith-1.5-35B, pi coding agent in the sandbox, thinking off)

* **Intel seed generation** works against the real model: 5 of 10 candidate advisories became valid seeds (the rest were dropped by the validator: literal URL, no
  placeholder, too long, or commentary). Run with the pi agent: **0 of 10** runs achieved the critical objective (no exfiltration to the canary server); **10 of 10**
  hit the weaker "secret printed after untrusted content" objective.
* **That 10/10 must not be read as an attack success rate.** The no-attack control hit the same objective **3 of 6** times (the model reads `.env` on its own), so the
  difference (10/10 vs 3/6, one-sided Fisher p = 0.036) is a modest effect on a high-severity-only objective, from tiny samples and one model. The report, correctly,
  rates the run as having no critical finding.
* **Live fork** against the real model and pi: after fixing a bug it exposed (recorded absolute workspace paths pointed at a deleted directory; the cassette now
  rebases them to the fork's workspace), the replayed README read succeeds and the live model continues. One fork with the guard enforcing at step 3 did not
  reproduce the printed secret; that is one sample.

## Control-centre round (dashboard, monitoring, TUI, multi-stage, evaluation)

| Built | Verified |
|---|---|
| `internal/sysmon` (host, process tree, sandbox usage, docker stats), `/api/status`, history, SSE stream, `/metrics`, `/api/about` | fixture-parser tests, live read on this machine; the Status page rendered with real data; Prometheus target UP; Grafana datasource and dashboard provisioned and queried |
| Dashboard: **Status** (landing route), **Reports** (summary with evaluation, generate, preview, download, zip), **Settings** (defaults, guard defenses, model test, sync, graph reset, role-aware), **About** (key-feature matrix, architecture, licences) | headless-browser screenshots for admin/operator/viewer; report generation, PDF preview, download and zip exercised end to end |
| Run control: `POST /api/runs/{id}/cancel`, catalog-validated launch parameters (`/api/catalog`) | cancel verified on a running process group only partially (the test run finished before the cancel; unit tests cover the parts) |
| Optional Prometheus + Grafana (`scripts/stack.sh up --observability`) | stack started, hardened (non-root, caps dropped, read-only, loopback only) |
| `internal/eval` and `avhsol summary`: one evaluation with Wilson intervals and control comparison | unit tests including a hand-checked Fisher p-value (0.036 matches the real run) |
| Multi-stage attacks: fresh-session follow-up, `multi_stage` oracle, stages in path/report/graph, `inbox-memory` scenario | oracle and breach unit tests; offline pipeline run; see the real-model result below |
| Terminal UI (`avhsol` / `avhsol tui`), Bubble Tea | unit tests; driven through a pseudo-terminal: menus, forms, audit, an offline campaign with live output and evaluation, traces, intel, Doctor, Status |

### Real-model multi-stage result (Ornith-1.5-35B, simulated-tool harness, thinking off, scratch run directory)
12 attack runs (4 seeds x 3 repeats) and 3 no-attack controls on `scenarios/inbox-memory.yaml`:
* **Memory foothold** (stage 1: the agent saved an outsider's planted note to long-term memory): **4 of 12** (33%, 95% CI 14-61%) versus **0 of 3** controls. Higher than the control, but too few runs to tell it from chance (one-sided p = 0.36).
* **Full chain** (stage 2, a fresh session, recalled the note and sent data outside): **0 of 12**; no email to an outside address in any run.
* So the platform can detect and label a multi-stage attack and the model is partly vulnerable to the first stage, but **this model did not complete the chain**. The pipeline's positive case is demonstrated only with the simulated model (labelled) and by unit tests; no real-model multi-stage exploit has been observed.

## Not verified / not built

* **Real agents**: `targets/claude-code.yaml` and `targets/mcp-example.yaml` were not run against the real CLIs. The Anthropic translation was not run with a real model.
* No micro-VM tier; the simulated-tool harness's bash is Landlock-only.
* Intel: no scheduler, no dependency-aware matching, no UI; probe corpora (garak/PyRIT) not ingested.
* TRIVEKTRA eBPF findings are not read back into traces; no TLS on database ports; single-user token model.
* Evidence base is still one model and small samples (see README).
