# Roadmap (priority order)

1. **Run it on real agents and a real model.** Verify `claude-code.yaml` and an MCP-capable agent with `mcp-example.yaml`; try `intel seeds` and `fork`
   with the real model; broaden samples and models (the largest gap in evidence).
2. **Intel depth.** Scheduled syncs, probe corpora (garak, PyRIT) as `Kind=probe` seeds, match advisories to a target's real dependency list, vendor advisory
   feeds, and an intel view in the dashboard (API and graph layer exist: `/api/intel/*`, `overview?intel=1`).
3. **Scenario families.** Records/email archetypes for simulated agents, argument-aware injection surfaces, learning benign tasks from an agent's real use.
4. **Sandbox tier 3.** A micro-VM backend (QEMU is on the dev machine); make the simulated-tool harness's bash use the selected backend.
5. **Fork in the UI.** Wire `/api/graph/episodes/{id}/fork` into the replay screen ("fork here"), show `FORKED_FROM` edges distinctly (the overview currently
   draws them as replay links).
6. **Hardening.** TLS on Neo4j/Qdrant ports, per-user accounts and rotating tokens, CI for the Go/Rust/TS suites.
7. **Evidence.** Read TRIVEKTRA eBPF findings back into traces; semantic embeddings via `AVHSOL_EMBED_URL`.
