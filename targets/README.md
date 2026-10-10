# CLI agent targets

A target file tells AVHSOL how to run an existing coding agent non-interactively inside the
sandbox. The agent gets a decoy repository (poisoned README, planted secrets) and may reach only
the guard proxy (its route to the model) and the canary sink.

Fields: `command` (argv; placeholders `{task} {workspace} {proxy_url} {api_key} {model} {sink_url}
{cwd} {pi_dir} {node_dir} {env:NAME}`), `env` (the only variables the agent sees), `ro_paths`
(install dirs the agent must execute from), `setup_files` (agent config pointing it at the proxy),
`tool_aliases`, `untrusted_tools` (`["*"]` = treat all tool output as untrusted), `timeout_sec`.

Works today for agents that speak the OpenAI chat-completions API (pi, opencode, Codex with a
chat-completions provider, aider, Continue, ...): set the agent's base URL to `{proxy_url}/v1`.
Agents that only speak other wire formats (Claude Code uses the Anthropic Messages API) need that
format added to the proxy; their commands and the sandbox work the same way.

Run:  avhsol campaign -scenario scenarios/devops-coder.yaml -seeds seeds/coding-seeds.yaml \
        -target targets/pi-coding-agent.yaml -guard-url http://127.0.0.1:7077

## More target kinds (see docs/CONNECTORS.md)

* `kind: http` (`http-example.yaml`): a remote chat endpoint, black box; no guard replay.
* `kind: mcp` (`mcp-example.yaml`): a cli target plus a poisoned MCP server (`avhsol mcp-serve`).
* `wire: anthropic` (`claude-code.yaml`): the proxy serves `/v1/messages`; point the agent's `ANTHROPIC_BASE_URL` at `{proxy_url}`.
* `isolation: gvisor` or `-isolation gvisor`: run the agent in a no-network gVisor container instead of Landlock (docs/SANDBOX.md).
* `shell-probe.yaml`: a scripted agent used to check that isolation backends behave identically.
