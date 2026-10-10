# Architecture

```
dashboard (Next.js) ──REST/SSE, bearer tokens──▶ core (Go)
core ──spawns/records──▶ harness (TS, pi fork)  ──LLM calls──▶ guard proxy (Rust) ──▶ user's LLM endpoint
core ──runs closed-box agents in──▶ avhsol-sandbox (Rust: Landlock+seccomp+rlimits)
core ──▶ Neo4j (bitemporal graph) + Qdrant (vectors)
```

* **core/** — campaigns (`internal/campaign`), adaptive attacker with bandit search (`attacker`), oracles (`oracle`), static auditor (`audit`),
  hash-chained Ed25519-signed traces (`trace`, `sign`), graph + GraphRAG (`graph`, `vec`), reports (`export`, `breach`, `advisory`),
  HTTP API (`api`), closed-box CLI runner (`cliagent`), policy bridge to the guard (`guard`), model client (`llm`).
* **guard/** — `avhsol-guard` policy engine (defenses D1–D7: fence untrusted, strip hidden/scan args, capability limits, taint egress block,
  secret-in-egress, protected paths, approval for destructive); `avhsol-proxy` records every LLM exchange and strips denied tool calls in
  enforce mode; `avhsol-sandbox` confines closed-box agents (shares the host kernel; not a VM).
* **pi/packages/avhsol** — target and attacker agents on the vendored pi fork.
* **Trust boundaries:** target content is untrusted; the model is never the success authority; secrets are redacted before storage;
  the API binds loopback and authenticates by role.
* **Data flow of a run:** attack episode → trace (steps, guard decisions, oracle verdicts) → signed → ingested to graph (`-graph`) → report/graph UI.
