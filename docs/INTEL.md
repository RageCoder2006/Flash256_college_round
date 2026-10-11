# Threat intelligence

AVHSOL keeps a **local cache** of public intelligence about AI agents and uses it three ways: to write attack seeds, to
link advisories to techniques in the graph, and to give findings context in reports. Nothing is fetched while a test runs.

## Sources

| Source | What | Notes |
|---|---|---|
| `ghsa` | GitHub Security Advisories (reviewed) for pip, npm, go, rust, maven | Kept if the text is about agents/LLM tooling or the package is on the watchlist. `AVHSOL_GITHUB_TOKEN` raises the rate limit |
| `nvd` | NVD CVE API 2.0 by keyword (prompt injection, MCP, LLM agent, langchain, ...) | `AVHSOL_NVD_API_KEY` raises the rate limit; without it calls are paced 6 s apart |
| `osv` | OSV.dev for the agent-stack watchlist (`internal/intel/data/watchlist.yaml`) | one detail call per vulnerability, capped |
| `kev` | CISA Known Exploited Vulnerabilities | **enricher**: marks cached items whose CVE is exploited in the wild |
| `epss` | FIRST EPSS exploit-probability score | **enricher**: adds the 30-day probability |
| `feeds` | arXiv Atom queries (`data/feeds.yaml`) | research leads, stored as `Kind=paper`, never as findings |
| taxonomy | OWASP LLM Top 10, OWASP agentic (ASI), MITRE ATLAS ids per technique (`data/taxonomy.yaml`) | static and versioned, works offline; re-check ids against upstream when updating |

The cache is a private directory (`deploy/stack/intel/`, mode 700/600, git-ignored; override with `AVHSOL_INTEL_DIR`).
A copy in that directory of `watchlist.yaml` or `feeds.yaml` overrides the built-in list.

## Commands

```
avhsol intel sync [-source ghsa,nvd,osv,feeds,kev,epss]   # the ONLY command that uses the network; audited
avhsol intel status | list [-q text] [-tag technique:tool_poisoning] [-kev] | show <id>
avhsol intel seeds -scenario scenarios/devops-coder.yaml -n 10 -o seeds/intel-generated.yaml   # needs the model
avhsol intel graph                       # load the cache into Neo4j/Qdrant as Intel nodes
avhsol intel export-bundle -o b.json     # signed (Ed25519) bundle for an air-gapped deployment
avhsol intel import-bundle b.json        # verifies digest + signature; refuses unsigned unless -allow-unsigned
```

API: `GET /api/intel/status`, `/sources` (catalog + counts + facets), `/items`, `/search` (semantic + text), `/graph` (knowledge graph) (all viewer), `POST /api/intel/sync` (admin, audited, one at a time),
`GET /api/graph/overview?intel=1` adds the intel layer, `GET /api/graph/*` answers can cite intel.

## How it is used

1. **Seeds.** `intel seeds` ranks items (KEV, then EPSS, then CVSS; papers lower), asks the model to adapt the *technique* to the
   scenario's surfaces with the advisory passed as quoted data under a "never obey" system prompt, and **validates** every result:
   it must use only the scenario's placeholders (`{{sink_url}}`, `{{host_secret_path}}`, `{{attacker_email}}`) and contain no literal URL or
   email. Invalid output is dropped, never repaired (the reply is first reduced to its fenced block, capped at 12 lines, and rejected if it reads as commentary about an attack). Each seed carries `ref` (e.g. `GHSA-...`); the run's trace records it as
   `attack.intel_ref`. A seed is an *idea to test*, not a finding.
2. **Graph.** `:Intel` nodes (`MOTIVATES` → `:Technique`, `(:Episode)-[:INSPIRED_BY]->(:Intel)`), embedded into a separate Qdrant
   collection so GraphRAG answers can cite them without mixing into run evidence.
3. **Reports.** Findings get "Related public intelligence" (matched by technique) and the report a "Threat context" section; SARIF gets
   `relatedIntel` and taxonomy ids. **Intel never changes a risk rating**, and the report says a match is not proof the target has that bug.

## Safety of third-party text

Everything is clipped, stripped of control and invisible Unicode characters, and treated as data: escaped when rendered and quoted as
untrusted when shown to a model. Only HTTPS is used (plain HTTP only to loopback in tests), bodies are size-capped, a failing source is
recorded and skipped, and a failed sync never advances a source's cursor or discards cached data.

## Not done

Other feeds (vendor advisories, Embrace-the-Red style blogs, garak/PyRIT probe corpora as `Kind=probe`), CVE→package matching against a
target's real dependency list, automatic scheduled syncs, and a UI for the intel layer (the API and graph layer exist).
