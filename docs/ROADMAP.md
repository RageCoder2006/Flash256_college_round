# Roadmap (priority order)

1. **`avhsol replay` and the exploit-corpus gate.** Re-run a trace from its recorded model answers (no model) and check the outcome reproduces; and
   `avhsol regress`, which replays every stored successful exploit plus the benign suite against a candidate policy and exits non-zero if an old exploit
   reopens or a legitimate task breaks. Both are small now: `fork`, `policy-test` and `internal/eval` already do the heavy parts.
2. **Run it on real agents and more models.** Verify `claude-code.yaml` and an MCP-capable agent with `mcp-example.yaml`; broaden samples and models (the
   largest gap in evidence); run the multi-stage scenario against more models.
3. **More multi-stage routes.** Payload split across documents, tool-result chains, and a persistence path that is not memory (config files, skills),
   each as its own stage type.
4. **Intel depth.** Scheduled syncs, probe corpora (garak, PyRIT) as seeds, matching advisories to a target's real dependency list, vendor feeds.
5. **Monitoring depth.** Remote hosts (node agents), per-episode charts that persist after the run, alert rules in Prometheus, a memory limit for Landlock-confined agents (cgroups).
6. **Sandbox tier 3.** A micro-VM backend; make the simulated-tool harness's bash use the selected backend.
7. **Fork from the replay screen** in the dashboard, and `FORKED_FROM` edges drawn distinctly.
8. **Hardening.** TLS on Neo4j/Qdrant ports, per-user accounts and rotating tokens, CI running `scripts/check.sh` (workflow added, untested).
