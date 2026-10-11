# Frontend

Next.js 16 / React 19, dark "neural" theme (tokens in `app/globals.css`; Unbounded / Figtree / JetBrains Mono; coral = breach, mint = held, violet/cyan = neural).

| Route | Page |
|---|---|
| `/` | Landing page that doubles as the pitch (`app/page.tsx`, `app/landing.css`): scroll through 16 animated sections, then open the live demo. Content lives in `components/pitch/slides.tsx`, diagrams in `components/ArchDiagram.tsx` and `components/pitch/diagrams.tsx` |
| `/console` | **Status**: live environment, host, sandbox, guard and run activity (the first page after sign-in) |
| `/console/verdict` | Verdict + report downloads |
| `/console/reports` | Reports: runs, executive summary and evaluation, generate / preview / download / zip |
| `/console/settings` | Settings: defaults, guard defenses, model test, intel sync, graph reset (role-aware) |
| `/console/about` | About: what it is, versions, key-feature matrix, architecture, licences |
| `/console/graph` | **3D neural graph** |
| `/console/traces`, `/console/traces/[id]` | Trace list and detail (breach line, causal graph, bitemporal beliefs) |
| `/console/run` | Start campaigns, live event stream |

**Neural graph:** `lib/graph3d.ts` (scene model, colours, lane layout for replay, activation→appearance), `components/graph3d/NeuralGraph.tsx`
(react-force-graph-3d + three: glow sprites, anime.js tweening of per-node display value), `app/console/graph/page.tsx` (chat, replay, overview).
Click an episode to lazily load its steps and replay them on a timeline (play/pause/scrub/speed). A chat question calls `/api/graph/ask` (falls back to
`/api/graph/activate` on 403/503) and lights up the activated nodes while dimming the rest.

Animations use anime.js v4 and honour `prefers-reduced-motion`. Auth: tokens live in `sessionStorage` (`lib/api.ts`).

## Command-centre replay (neural graph page)
* Click an episode (or a replay chip) to lay the run out as a timeline board: steps on lanes (results above, calls in the middle, guard below), the episode at the left end, artifacts above/below the step that touched them (`layoutRun` in `lib/graph3d.ts`). A chase camera follows the current step.
* Left column: mission summary, telemetry counters, threat meter, attack-chain checklist (`lib/telemetry.ts`) and a live event feed. Bottom: narration card with typed text plus transport controls.
* Narration comes from `POST /api/graph/episodes/{id}/narrate` (analyst; one LLM call grounded in the graph's provenance path, cached) and falls back to rule-based text from `GET` (viewer). The card shows which source was used.
* Right dock (minimisable): **Inspect** (details and connections for the clicked node, `components/graph3d/Panels.tsx`) and **Ask graph** (chat; lights up activated nodes).
* The console sidebar can be hidden (`components/ConsoleShell.tsx`, remembered in localStorage). The landing page has a full SVG architecture diagram (`components/ArchDiagram.tsx`).

## Threat intelligence (`/console/intel`)
Three tabs in the console theme (`components/intel/*`, styles under "threat intelligence" in `globals.css`):
* **Data sources** — a card per source (GHSA, NVD, OSV, KEV, EPSS, arXiv feeds, taxonomy): what it is, record counts, last sync, health, whether its optional API key is set. Summary tiles for the whole cache. Admins can sync all or one source (`POST /api/intel/sync`).
* **Search & browse** — ask the data sources a question (`GET /api/intel/search`: matches by meaning first when the vector store is connected, then by text) or filter by source, kind, attack technique and "exploited only"; a detail panel shows the record, its CVSS/EPSS, affected packages, mapped taxonomy and a link to the original.
* **Knowledge graph** — `GET /api/intel/graph` builds records, their data source, attack techniques, taxonomy ids (OWASP LLM / ASI / MITRE ATLAS), affected packages and same-vulnerability links (`ALIAS_OF`) from the local cache, drawn with the same 3D component as the run graph. A question lights up the matching records and, more faintly, what they connect to; clicking any node opens its details and connections.
All record text is third-party data: React escapes it and links open with `noopener noreferrer nofollow`.

## Landing page as a pitch
Scroll (or use ↑/↓, PgUp/PgDn) through: problem, why testing falls short, what it is, how a run works, evidence, architecture, threat intelligence, test any agent, containment, graph and replay, replay and fork, the report, results (with caveats), platform security, honest status, demo. Sections animate in once with anime.js (honouring reduced motion), a right-hand dot rail and a progress bar show where you are, and **N** toggles speaker notes for the current section. The last section links straight into the console, threat-intel page and neural graph.

## Status, Reports, Settings, About
* **Charts** are hand-built SVG in `components/charts/charts.tsx` (`Spark`, `Area` with hover read-out, `Ring`, `Cores`, `Stack`, `Tile`); live data from `lib/status.ts` (`useStatus`: history, then an SSE stream that reconnects).
* **Reports**: `components/reports/RunSummary.tsx` renders the report as data (executive summary, evaluation with 95% interval bars and control comparison, scope, findings you can expand, defenses, recommendations, limitations, integrity). Previews run **HTML in a frame with `sandbox=""`** (no scripts, no same-origin) and PDF in a frame; text formats are escaped. Saved reports live in `<run>/reports/` with a sha256.
* **Settings** never stores or shows secrets; the model section shows only reachability and "key set". Controls a role cannot use are disabled with the reason.
