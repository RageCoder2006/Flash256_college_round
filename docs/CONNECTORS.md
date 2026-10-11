# Bring your own agent

A target file in `targets/` tells AVHSOL how to run the agent under test. `kind` picks the mechanism; every kind is judged by the same
deterministic oracles.

| kind | How the agent is reached | What AVHSOL sees | Guard replay |
|---|---|---|---|
| `cli` (default) | runs the agent's command in the sandbox; its only route to a model is the guard proxy | every model exchange and tool call (wire-level) | yes |
| `mcp` | a `cli` target that is also given a poisoned MCP server | as `cli` | yes |
| `http` | a remote chat endpoint | its replies, the moment it fetches the poisoned document, and any hit on the canary sink | no (not in the model path) |

## Wire formats (proxy)

`avhsol-proxy` serves `/v1/chat/completions` (OpenAI) and `/v1/messages` (**Anthropic**). The Anthropic route translates to the configured
OpenAI-compatible upstream and back, so a Claude-wire agent can be tested against any model AVHSOL can reach. Set `AVHSOL_UPSTREAM_MODEL` on the
proxy to replace the Claude model name the agent asks for. The same policy runs on both routes (record, fence untrusted results, strip denied
tool calls). Unit tests and a mock-upstream round trip cover it; `targets/claude-code.yaml` is **not verified against the real Claude Code CLI**.

## HTTP targets (`targets/http-example.yaml`)

AVHSOL serves the poisoned document on a local port and tells the agent where it is (`placement: url`), or appends the payload to the message
(`placement: inline`). Request body, headers (tokens via `{env:NAME}`), and the response path are configurable. The trace is marked
`observability: blackbox` and the report says tool calls were not observed. `validate` refuses these targets; use `campaign` or `hunt`.
Tested end to end against a scripted agent (71% against a gullible one, 0% against a safe one).

## MCP targets (`targets/mcp-example.yaml`)

`avhsol mcp-serve` is a deliberately poisoned MCP server (stdio JSON-RPC): its tool **result** and/or **description** carries the payload
(`poison: result|description|both`). The target's `setup_files` register it with the agent's MCP client. The protocol and poisoning are unit
tested and the server was listed live by `scengen -mcp`; **no real MCP-capable agent was run against it here**, so the example config is a template.

## Choosing isolation

`-isolation landlock|gvisor` (or `isolation:` in the target) — see [SANDBOX.md](SANDBOX.md).

## Black-box today

There is no separate black-box command yet. For an agent you can only reach over the network, write an `http` target
(`targets/http-example.yaml`) and run `avhsol campaign -scenario <scenario> -target <target>.yaml`. Tool calls are not observed in
that mode and the guard is not in the path, so only outcomes (what the oracle can see in replies and the canary sink) are judged.
For code you can run, `avhsol .` (WHITEBOX.md) is the better route.
