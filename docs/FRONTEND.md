# Frontend

Next.js 16 / React 19, dark "neural" theme (tokens in `app/globals.css`; Unbounded / Figtree / JetBrains Mono; coral = breach, mint = held, violet/cyan = neural).

| Route | Page |
|---|---|
| `/` | Landing page (`app/page.tsx`, `app/landing.css`): hero lattice, features, flow, architecture, results with caveats, status |
| `/console` | Verdict + report downloads |
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
