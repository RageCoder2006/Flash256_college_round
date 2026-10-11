# AVHSOL as an MCP server

AVHSOL exposes its own tools to Claude Code (or any MCP client) so an agent can scan code, read runs and pull reports.
The list is one registry (`internal/tools`); the Settings page shows it in a drop-down and chooses what is served.

## Connect

```
claude mcp add avhsol -- avhsol mcp                     # stdio, runs as you; analyst role by default
claude mcp add avhsol -- avhsol mcp --role viewer       # read-only
claude mcp add avhsol -- avhsol mcp --role operator --allow-launch   # may also start audits
```

Over HTTP (Settings > Tools > "Serve the selected tools at /mcp", admin only):

```
claude mcp add --transport http avhsol http://127.0.0.1:8787/mcp --header "Authorization: Bearer $AVHSOL_TOKEN"
```

The HTTP endpoint uses the dashboard API's tokens and roles, is loopback-only like the API, and every `tools/call` is written to the
audit log.

## Tools

| Tool | Effect | Role |
|---|---|---|
| `avhsol_scan_codebase` | reads: static whitebox audit of a directory | viewer |
| `avhsol_audit_scenario` | reads | viewer |
| `avhsol_list_catalog`, `avhsol_list_runs`, `avhsol_list_traces`, `avhsol_get_trace`, `avhsol_verify_trace`, `avhsol_summary`, `avhsol_intel_search`, `avhsol_status` | reads | viewer |
| `avhsol_export_report` | writes a report into the run's directory | analyst |
| `avhsol_audit_codebase` | **launches**: `avhsol <path>`, which runs the audited agent's code in a sandbox when not static | operator, off by default |

Runs are addressed by name from `avhsol_list_runs`; a path is never accepted, so a client cannot open arbitrary files through them.

## Safety

* Results contain text attackers can write (trace payloads, scanned source, advisories). They are returned inside an
  `untrusted_content` block with a fixed warning and are truncated; the server's instructions tell the model to treat them as data.
* Tools that launch agents are absent from `tools/list` unless allowed (`--allow-launch`, or the Settings allow-list) and the
  caller's role is operator; a hidden tool cannot be called.
* Not exposed yet: graph questions (`ask`, `why`), verdict corrections and guard checks (they need the Neo4j/Qdrant stack).
