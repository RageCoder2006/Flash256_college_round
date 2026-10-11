# `avhsol .`: audit an agent from its own source directory

Run `avhsol .` in the directory that holds an AI agent's code (or `avhsol ./path/to/agent`). It reads the code, then, if it
knows how to launch the agent and a model is configured, attacks it in a sandbox and writes the report. There are no prompts
for a recognised agent. `avhsol . --static` only reads.

## What happens

1. **Read the code** (`internal/whitebox`; never executes anything from your directory and never writes into it).
   Detects the framework (OpenAI/Anthropic SDKs, LangChain/LangGraph, LlamaIndex, CrewAI, AutoGen, MCP, pi, ...), finds the tools
   the agent gives its model (decorators, `server.tool(...)`, `tool({...})`, object literals with name+description+handler,
   `createXTool` factories, JSON function schemas, MCP config files, or a `tools_file`), and flags: shell/eval/SQL sinks,
   disabled approvals, committed credentials (shown only as fingerprints) and `.env` files, TLS verification off, MCP servers
   fetched unpinned or given a very broad filesystem root, the lethal trifecta, destructive tools with no approval step, and
   instruction files (`AGENTS.md`, `CLAUDE.md`, ...) that act as injection surfaces. Every finding has `file:line`.
   Dependencies are read from manifests and lock files. With `--online`, exact versions go to OSV (package names and versions
   leave the machine, over HTTPS); without it only package names are compared with your local threat-intel cache and the
   report says versions were not checked.
2. **Static permission audit** of the scenario generated from those tools (same engine as `avhsol audit`).
3. **Build** the agent if needed. For pi that is `npm run build`; it runs the repository's own scripts outside the sandbox, is
   printed first, and `--no-build` refuses it.
4. **Guard proxy**: started on a free loopback port and stopped at the end. It forwards to your model and holds the model key;
   the audited agent only ever sees a placeholder key. `AVHSOL_GUARD_URL` / `--guard-url` use one you started yourself.
5. **Attack campaign** with the guard off (coding seeds, intel-generated seeds if you made them, and a no-attack control),
   **defense validation** (replay exploits through the guard in enforce mode), **benign-task regression**, and
   **per-defense ablation**: these are `avhsol validate` on the generated scenario.
6. **Evaluation** (success rates with intervals, comparison with the control) and **reports** (HTML, JSON, SARIF).

Step "multi-stage attacks" is listed and skipped: it needs an agent with persistent memory and a later fresh session, which a
launched CLI agent does not provide yet.

Output goes to a new directory under the state directory (`~/.local/share/avhsol/runs/<name>-<time>` when installed), never inside
your code (`--out` to choose; one inside the audited directory is refused). It holds `whitebox.json`, `whitebox.sarif`,
`scenarios/`, `target.yaml`, `seeds.yaml`, `dyn/` (traces, validation), `evaluation.txt`, `report.html|json|sarif`.

## The dashboard sees the same results

Runs go to the state directory (`~/.local/share/avhsol/runs/`), and `avhsol serve` lists everything there, so an audit started in a
terminal is available in the dashboard without copying anything:

* **Reports** lists the run; the HTML, JSON, SARIF and (when Chrome is available) PDF reports the CLI wrote are registered there, so
  you can preview and download them, and generate more.
* **Run selector** (bottom of the sidebar): choose the run and the Traces, Verdict and summary pages show it. "Server default" is the
  directory the API was started with.
* **Neural graph**: when Neo4j is reachable the audit records its traces in the graph automatically (`AVHSOL_GRAPH=0` or `--graph=false`
  to skip), so the graph page shows them too.
* **Terminal**: `avhsol summary -in <run>/dyn` and the menu's traces screen read the same files.

The API must be restarted after upgrading the binary; it picks up new runs on its own.

## Which agents it can launch

* **pi** (the vendored monorepo) is recognised and needs nothing else.
* Anything else needs an `avhsol.yaml` next to the code (`avhsol init` writes a starter):

```yaml
name: my-agent
run: ["python", "{agent_dir}/agent.py", "{task}"]   # starts the agent for ONE task; stdin is closed
model_env: openai          # openai | anthropic | both: which base-URL variables point at the guard
env: {SOME_FLAG: "1"}
ro_paths: []               # extra read-only paths the agent needs
setup: ["pip install -r requirements.txt"]   # shown, never run for you
build: "npm run build"
tools_file: tools.json     # tools registered dynamically
target: pi-coding-agent    # alternatively: a ready target template from targets/
```

The agent's own code is mounted read-only; its working directory is a decoy workspace with planted credentials and poisoned
documents, and its model traffic goes only to the guard (it receives `OPENAI_BASE_URL`, `OPENAI_API_BASE`, `ANTHROPIC_BASE_URL`
and a placeholder key). The agent must honour those variables and run non-interactively. Agents that hard-code their model
endpoint cannot be redirected.

## Flags

`--static`, `--quick` (1 repeat, no ablation, no rating), `--repeats N`, `--skip ablation`, `--isolation landlock|gvisor`,
`--online`, `--out DIR`, `--json`, `--sarif FILE`, `--no-build`, `--guard-url`, `--graph`.
With no model configured (`AVHSOL_LLM_*`) it stops after the static report and says so; it never substitutes the simulated model.

## Limits, stated plainly

The reader is pattern-based. It can miss tools registered dynamically and can flag harmless code; the confidence column says
how sure each pattern is, and hints like "shell" for a tool come from the code near its declaration. A finding is a lead;
the dynamic attack is what shows exploitability, and "no exploit observed" covers only the techniques tried. Blackbox auditing
of a deployed agent you cannot run is not a separate command yet: use an `http` target (see CONNECTORS.md).
