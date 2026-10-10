# Status

## Implemented
* Attack pipeline: seeds, adaptive hunt (bandit, model-written payloads, reliability re-runs, minimisation), deterministic oracles, canary sink.
* Guard (Rust) with defenses D1–D7, wire-level proxy, sandbox; guard replay, benign regression, defense ablation, `policy-test` time machine.
* Signed hash-chained traces; redaction to fingerprints.
* Bitemporal Neo4j graph, Qdrant vectors, GraphRAG with citations, spreading activation, overview/activate endpoints (tested live).
* Hardened API with roles and audit log. Report engine (HTML/PDF/MD/JSON/SARIF) driven by JSON skeletons.
* Dashboard: dark redesign, landing page, console, 3D neural graph with run replay and chat-driven activation, anime.js motion.
* Targets: simulated HR and devops-coder agents; closed-box pi coding agent.

## Not implemented
See [ROADMAP.md](ROADMAP.md): bring-your-own-agent connectors, automatic scenario generation, live fork-from-step revive, stronger sandbox,
TLS on DB ports, TRIVEKTRA findings ingestion, and restyling the older console pages (Verdict, Traces, Run) fully into the new motion language.

## Evidence so far
One model (Ornith-1.5-35B), small samples; see the README for numbers and caveats.
