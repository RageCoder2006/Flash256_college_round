# Graph

* **Store:** Neo4j 5 (graph) + Qdrant (vectors), `deploy/stack`. Init with `avhsol graph init`; ingest runs with `-graph` or `avhsol graph ingest`.
* **Bitemporal:** valid time (when it happened) vs record time (when recorded or revised). Corrections close the old belief and link the new one;
  `Clock.Where` is the single source of temporal predicates. Secrets are fingerprints before storage.
* **Nodes/edges:** episodes, steps (`tr-xxx#seq`), payloads, techniques, resources, tools, secrets, defenses; edges NEXT, TAINTED_BY, RETURNED,
  EVALUATED, READ/ACCESSED/LEAKED/EXPOSED, STOPPED/BY_RULE, REPLAY_OF, PLANTED, INSTANCE_OF, USED, TOUCHED.
* **GraphRAG:** `graph.Ask` embeds the question (lexical offline embedder by default; set `AVHSOL_EMBED_URL` for semantic), retrieves similar steps from Qdrant,
  expands through the graph, and has the model answer with citations. `Probe` is the model-free variant.
* **Spreading activation** (`core/internal/graph/overview.go`, `Activate`): each hit gets a level 0.55–1.0 from its score; it spreads along causal edges
  ≤2 hops with decay 0.6; episode/payload/technique/defense/tool nodes light more faintly. The UI maps levels to glow/size/opacity.
* **API:** `GET /api/graph/overview` (viewer; `episodes, scenario, target, model, simulated`), `GET /api/graph/episodes/{id}/{subgraph,path,beliefs}`,
  `POST /api/graph/ask` (analyst; model), `POST /api/graph/activate` (viewer; retrieval only), `POST /api/graph/correct`.
* **Tests:** `core/internal/graph/graph_integration_test.go` runs against the live stack.
* **Narration:** `Store.Narrate` (`core/internal/graph/narrate.go`) writes a sentence per step for the replay screen; the recorded steps are passed to the model as data, never instructions. Rule-based notes are the fallback.
