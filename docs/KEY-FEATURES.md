# The seven key features: what is done, honestly

The platform was built against seven requirements. This is the account of each, updated after every round. "Done" means built, tested,
and exercised on real runs; where a gap remains it is named.

| # | Key feature | State | Where it lives | Gap |
|---|---|---|---|---|
| 1 | **Autonomous attack discovery** | Done | `avhsol hunt`: bandit search over technique x surface x operator, model-written payloads, reliability re-runs, payload shrinking; seeds written from public threat intelligence (`avhsol intel seeds`); scenarios generated from a tool list (`avhsol scengen`) | Evidence so far is one model and small samples |
| 2 | **Multi-stage attack analysis** | Done (one persistence path) | Provenance edges (`TAINTED_BY`), the causal path and breach line with **conversation stages**, a multi-session scenario (`scenarios/inbox-memory.yaml`) where stage 1 plants a memory note and a later *fresh* session recalls and acts on it, a `multi_stage` oracle, `RECALLS` edges in the graph, stage labels in the report timeline | Covers persistent-memory poisoning; other multi-stage routes are not modelled as distinct stages. With the real model the first stage landed 4 of 12 times but the chain never completed (0 of 12); the positive case is shown only with the simulated model and unit tests |
| 3 | **Tool and permission auditing** | Done | `audit.Static` (over-privilege, the lethal trifecta), `audit.Dynamic` (confused deputy), tool-role classification in `scengen` | None material |
| 4 | **Reproducible attack traces** | Done | Hash-chained, Ed25519-signed traces; secrets reduced to fingerprints; replay in the graph; `avhsol fork` re-walks a run and lets the live model take over | No model-free `replay` command that re-runs a trace from its recorded answers and checks the outcome |
| 5 | **Defense validation** | Done | `avhsol validate` (guard replay, benign regression, one-defense-at-a-time ablation), `avhsol policy-test` (replay recorded history through any policy, no model) | None material |
| 6 | **Security evaluation dashboard** | Done | Console: Status (live host and sandbox), Verdict, Neural graph and run replay, Threat intel, Traces, Reports (executive summary, evaluation with intervals, previews, downloads), Run, Settings, About | None material |
| 7 | **Regression testing** | Mostly done | Benign task suite with and without the guard (`-regress`), utility and false-positive counts, `policy-test` over stored exploits | No single CI gate that replays the whole stored exploit corpus against a candidate policy and exits non-zero if an old exploit reopens |

## What changed in the latest round
* **Status page and monitoring** (host CPU, RAM, swap, load, disk, network, temperatures, pressure, sandbox resource use, containers, environment health) with optional Prometheus and Grafana: see [MONITORING.md](MONITORING.md).
* **Reports page**: every run, executive summary, scope, findings, defense results, recommendations, limitations, integrity; generate, preview and download in html, pdf, md, json and sarif; zip a run's reports.
* **Settings, About, cancel**: defaults and controls, a documented account of what the platform is, and `POST /api/runs/{id}/cancel`.
* **One security evaluation** (`internal/eval`): exploit rate with 95% Wilson intervals, comparison with the no-attack control (Fisher exact), per-technique and per-defense results, shown identically by `avhsol summary`, the end of every run, the TUI, the dashboard and `/api/summary`.
* **Terminal UI** (`avhsol`, `avhsol tui`): see [TUI.md](TUI.md).
* **Multi-stage attacks**: see [SCENARIOS.md](SCENARIOS.md#multi-stage-scenarios).

## Still not built (and why it matters less)
`avhsol replay` (deterministic re-run from recorded answers) and the exploit-corpus CI gate were offered and deferred; both are small given
`fork`, `policy-test` and the evaluation code, and are first on [ROADMAP.md](ROADMAP.md).
