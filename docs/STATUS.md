# Status

## Implemented

**Testing pipeline** — attack seeds and an adaptive hunter (bandit, model-written payloads, reliability re-runs, minimisation); deterministic oracles and a canary
sink; Rust guard (D1–D7) and proxy; guard replay, benign regression, defense ablation, offline `policy-test`; hash-chained Ed25519-signed traces with secrets
redacted to fingerprints; report engine (HTML/PDF/MD/JSON/SARIF) driven by JSON skeletons.

**Graph** — bitemporal Neo4j graph + Qdrant vectors, GraphRAG with citations, spreading activation, per-step LLM/rule narration for replays, hardened role-based API
with a hash-chained audit log.

**Dashboard** — dark redesign, landing page with a full architecture diagram, console, 3D neural graph with command-centre replay, node inspector, chat dock,
hideable sidebar. (Frozen during the latest round.)

**Latest round (see [PLAN-intel-and-core.md](PLAN-intel-and-core.md))**

| Phase | Built | Verified |
|---|---|---|
| A. Threat intel | GHSA, NVD, OSV, KEV, EPSS, arXiv feeds, ATLAS/OWASP taxonomy, signed offline bundles, seed generation, Intel graph nodes, report enrichment, API | parser tests on fixtures; **live sync** of all sources (973 items, KEV and EPSS enrichment); live Neo4j test; report export with real cache |
| B. Connectors | Anthropic `/v1/messages` in the proxy; `http` targets (black box); `mcp` targets with a poisoned MCP server | Rust unit tests + mock-upstream round trip; HTTP target end to end (71% vs gullible, 0% vs safe); MCP protocol tests |
| C. Scenario generation | `avhsol scengen` (rules + optional model assist, lint) | unit tests; generated scenario ran a campaign; live MCP tool listing |
| D. Sandbox | `gvisor` backend, stdio port tunnel (`netmux`) | live container test; identical oracle results to Landlock (10/14 both) |
| E. Live revive | `avhsol fork`: harness history + closed-box cassette, edits, API, `FORKED_FROM` | harness vitest; end to end with a mock OpenAI-compatible model on both paths |

## Not verified / not built

* **Real agents**: `targets/claude-code.yaml` and `targets/mcp-example.yaml` were not run against the real CLIs. Fork and intel seed generation were not run
  against a real model (a scripted mock was used; the model endpoint was not configured in the build session).
* No micro-VM tier; the simulated-tool harness's bash is Landlock-only.
* Intel: no scheduler, no dependency-aware matching, no UI; probe corpora (garak/PyRIT) not ingested.
* TRIVEKTRA eBPF findings are not read back into traces; no TLS on database ports; single-user token model.
* Evidence base is still one model and small samples (see README).
