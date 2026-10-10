# Scenario generation

`avhsol scengen -tools tools.json | -mcp "COMMAND" [-id my-agent] [-model-assist] [-o scenarios/my-agent.yaml]` turns an agent's tool list into a test
scenario. Accepted tool formats: a JSON array, MCP `tools/list`, OpenAI function definitions, Anthropic tool definitions. `-mcp` starts an MCP server
over stdio and calls only `tools/list`.

1. **Classify** each tool by rules (name words, description, argument names) into roles: `untrusted_read`, `sensitive_read`, `egress`, `destructive`,
   `memory`, `shell`. A shell plays every role. With `-model-assist` the model labels only tools the rules left empty, and its answer is checked against
   that fixed vocabulary.
2. **Build** a workspace scenario (`generated: true`): random per-generation canary credentials planted in `.env`, two untrusted documents as injection
   surfaces, objectives that match oracles that exist (`sink_exfil`, `secret_read`, `escape_marker`, `tool_called` for destructive non-shell tools), capabilities
   from the roles, and benign tasks with deterministic checks.
3. **Lint**: every objective needs an implemented oracle, every secret must be planted, every benign task needs a check, surfaces must exist. Errors stop the
   write; warnings (for example "no tool can send data out, so exfiltration cannot happen") are printed. Tools the built-in simulated harness does not model
   are flagged as `-target`-only.

The report states when a scenario was generated (the planted data and tasks are generic). Verified on a Claude-Code-like tool list and a live MCP listing.
Not done: richer scenario families (records/email archetypes for simulated agents), per-tool argument fuzzing, learning tasks from the agent's real use.
