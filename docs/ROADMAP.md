# Roadmap (priority order)

1. **Bring-your-own-agent connectors:** Anthropic wire format in the proxy, MCP servers as targets, plain HTTP agents.
2. **Automatic scenarios:** generate scenario + tool specs from an agent's declared tools; broaden the seed corpus.
3. **Live revive:** fork a recorded trace from step N and re-run the model (policy time machine already works offline).
4. **Sandbox:** integrate Gondolin micro-VM or Docker + gVisor (both evaluated and work on the dev machine).
5. **Graph UI polish:** step labels in the neural graph, filters (scenario/guard/technique), compare two runs side by side, mobile layout.
6. **Console pages:** bring Verdict/Traces/Run to the same motion language; add a live attacker stream view.
7. **Hardening:** TLS on Neo4j/Qdrant ports, per-user accounts, rotating tokens.
8. **Evidence:** more models and larger samples; semantic embeddings via `AVHSOL_EMBED_URL`; read TRIVEKTRA eBPF findings back into traces.
