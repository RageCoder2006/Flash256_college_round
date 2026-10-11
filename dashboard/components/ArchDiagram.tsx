/** Full system diagram (landing page and pitch deck). Pure SVG; the dashed flow lines animate unless motion is reduced. */
export const C = { go: "#4dd8ff", rs: "#ffb454", ts: "#8f80ff", db: "#35e3ac", ui: "#ff5577", ext: "#8a9cc4", intel: "#c9a8ff" };

export function Box({ x, y, w, h, color, title, lines, small }: { x: number; y: number; w: number; h: number; color: string; title: string; lines?: string[]; small?: boolean }) {
  return (
    <g>
      <rect x={x} y={y} width={w} height={h} rx={10} fill="rgba(10,18,40,0.88)" stroke={color} strokeOpacity={0.55} />
      <text x={x + 12} y={y + (small ? 19 : 22)} fill={color} fontFamily="var(--font-jetbrains), monospace" fontSize={small ? 11 : 12.5} fontWeight={600}>{title}</text>
      {lines?.map((l, i) => (
        <text key={l} x={x + 12} y={y + (small ? 35 : 41) + i * 15} fill="#aab7d6" fontFamily="var(--font-figtree), sans-serif" fontSize={small ? 10.5 : 11.5}>{l}</text>
      ))}
    </g>
  );
}

export function Group({ x, y, w, h, color, label }: { x: number; y: number; w: number; h: number; color: string; label: string }) {
  return (
    <g>
      <rect x={x} y={y} width={w} height={h} rx={16} fill={color} fillOpacity={0.04} stroke={color} strokeOpacity={0.3} strokeDasharray="3 5" />
      <text x={x + 16} y={y + 22} fill={color} fontFamily="var(--font-jetbrains), monospace" fontSize={11} letterSpacing="2">{label}</text>
    </g>
  );
}

export function Flow({ d, color, label, lx, ly, anchor = "middle" }: { d: string; color: string; label?: string; lx?: number; ly?: number; anchor?: "start" | "middle" | "end" }) {
  return (
    <g>
      <path d={d} fill="none" stroke={color} strokeOpacity={0.5} strokeWidth={1.4} markerEnd={`url(#arr-${color.slice(1)})`} />
      <path d={d} fill="none" stroke={color} strokeWidth={1.6} strokeDasharray="2 14" strokeLinecap="round" className="arch-flow" />
      {label && <text x={lx} y={ly} textAnchor={anchor} fill="#8fa0c8" fontFamily="var(--font-jetbrains), monospace" fontSize={10}>{label}</text>}
    </g>
  );
}

export function Markers() {
  return (
    <defs>
      {Object.values(C).map((c) => (
        <marker key={c} id={`arr-${c.slice(1)}`} viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill={c} /></marker>
      ))}
    </defs>
  );
}

const MODULES: [string, string, string, string][] = [
  ["Campaign engine", "audit → attack → prove", "→ defend → regress", C.go],
  ["Adaptive attacker", "bandit search, model-", "written payloads, shrink", C.go],
  ["Deterministic oracles", "canary at sink, host file", "read, forbidden call", C.go],
  ["Static auditor", "over-privilege, lethal", "trifecta, confused deputy", C.go],
  ["Signed traces", "hash-chained, Ed25519,", "secrets → fingerprints", C.go],
  ["Graph + GraphRAG", "bitemporal ingest, vectors,", "spreading activation", C.go],
  ["Report engine", "JSON skeleton → HTML /", "PDF / MD / JSON / SARIF", C.go],
  ["Hardened API", "role tokens, throttle, audit", "log, security headers", C.go],
  ["Scenario generator", "tool list or live MCP server", "→ tested scenario + lint", C.go],
  ["Live revive (fork)", "re-walk a recorded run,", "model takes over at a step", C.go],
  ["Connectors", "CLI · MCP · HTTP targets,", "OpenAI + Anthropic wire", C.go],
  ["Threat intel layer", "sync · cache · seeds · graph", "· report context · bundles", C.intel],
];

export function ArchDiagram({ id = "arch" }: { id?: string }) {
  return (
    <figure className="arch-fig">
      <svg viewBox="0 0 1100 960" role="img" aria-labelledby={`${id}-t ${id}-d`} style={{ width: "100%", height: "auto" }}>
        <title id={`${id}-t`}>AVHSOL system architecture</title>
        <desc id={`${id}-d`}>A security engineer uses the Next.js dashboard, which talks to the Go control plane. Public threat intelligence is synced into the control plane on request. The control plane runs the TypeScript harness and a sandbox (Landlock or gVisor), routes all model traffic through the Rust guard proxy to the LLM endpoint, stores traces in Neo4j and Qdrant, and produces reports.</desc>
        <Markers />

        <Box x={250} y={14} w={220} h={50} color={C.ext} title="Security engineer" lines={["asks, replays, forks, reads the report"]} small />
        <Box x={190} y={104} w={520} h={64} color={C.ui} title="dashboard/ · Next.js 16 · React 19" lines={["Console · 3D neural graph · run replay command centre", "threat-intel sources, search and knowledge graph · reports"]} />
        <Box x={790} y={104} w={280} h={64} color={C.intel} title="Public threat intelligence" lines={["GHSA · NVD · OSV · CISA KEV · EPSS", "ATLAS · OWASP · arXiv research feeds"]} small />

        <Group x={30} y={206} w={1040} h={330} color={C.go} label="CONTROL PLANE · GO 1.22 · core/" />
        {MODULES.map(([t, a, b, c], i) => (
          <Box key={t} x={50 + (i % 4) * 255} y={240 + Math.floor(i / 4) * 94} w={238} h={78} color={c} title={t} lines={[a, b]} small />
        ))}

        <Group x={30} y={572} w={310} h={178} color={C.ts} label="HARNESS · TYPESCRIPT" />
        <Box x={46} y={602} w={278} h={62} color={C.ts} title="Target agent" lines={["pi fork with simulated tools, or a", "closed-box CLI / MCP agent"]} small />
        <Box x={46} y={674} w={278} h={62} color={C.ts} title="Attacker agent (pi)" lines={["plants hidden instructions,", "reads the trace, mutates"]} small />

        <Group x={370} y={572} w={330} h={178} color={C.rs} label="GUARD · RUST" />
        <Box x={386} y={602} w={298} h={62} color={C.rs} title="avhsol-proxy · OpenAI + Anthropic wire" lines={["records every exchange, strips denied", "tool calls, serves recorded answers (fork)"]} small />
        <Box x={386} y={674} w={298} h={62} color={C.rs} title="avhsol-guard policy · D1–D7" lines={["fence untrusted · strip hidden · capability", "limits · taint egress · protected paths"]} small />

        <Group x={730} y={572} w={340} h={178} color={C.rs} label="CONFINEMENT · LANDLOCK or gVISOR" />
        <Box x={746} y={602} w={308} h={62} color={C.rs} title="avhsol-sandbox  |  gVisor container" lines={["Landlock + seccomp, no root  |  runsc, no", "network, ports tunnelled over stdio"]} small />
        <Box x={746} y={674} w={308} h={62} color={C.ext} title="Decoy repo + canary sink" lines={["planted secrets and a local server that", "records any exfiltration attempt"]} small />

        <Box x={30} y={796} w={250} h={70} color={C.ext} title="LLM endpoint" lines={["any OpenAI-compatible /v1", "(your Unsloth model)"]} />
        <Box x={330} y={796} w={230} h={70} color={C.db} title="Neo4j 5" lines={["bitemporal trace + intel graph", "loopback · non-root · pinned"]} />
        <Box x={600} y={796} w={230} h={70} color={C.db} title="Qdrant" lines={["step, payload and intel vectors", "(lexical or semantic embedder)"]} />
        <Box x={870} y={796} w={200} h={70} color={C.ui} title="Security report" lines={["branded, signed digest", "findings · intel context · fixes"]} />
        <Box x={30} y={884} w={1040} h={56} color={C.intel} title="Local intel cache (private dir) + signed offline bundles" lines={["Nothing is fetched during a test. Sync is an explicit, audited command; an air-gapped site loads a verified bundle instead."]} small />

        {/* flows */}
        <Flow d="M360 64 L360 104" color={C.ext} />
        <Flow d="M360 168 L360 206" color={C.ui} label="REST + SSE · role tokens" lx={376} ly={192} anchor="start" />
        <Flow d="M930 168 L930 428" color={C.intel} label="sync (explicit, audited)" lx={946} ly={300} anchor="start" />
        <Flow d="M185 536 L185 572" color={C.ts} label="spawn · JSON" lx={197} ly={558} anchor="start" />
        <Flow d="M324 640 L386 640" color={C.rs} label="LLM" lx={355} ly={632} />
        <Flow d="M550 536 L550 572" color={C.rs} label="policy · decisions" lx={562} ly={558} anchor="start" />
        <Flow d="M900 536 L900 572" color={C.rs} label="run closed-box agent" lx={912} ly={558} anchor="start" />
        <Flow d="M746 640 L684 640" color={C.rs} label="model" lx={715} ly={632} />
        <Flow d="M520 750 C 520 784, 160 764, 160 796" color={C.ext} label="upstream to the model" lx={340} ly={778} />
        <Flow d="M355 536 C 355 640, 355 700, 355 796" color={C.db} />
        <Flow d="M715 536 C 715 640, 715 700, 715 796" color={C.db} />
        <Flow d="M1070 470 C 1096 470, 1096 831, 1070 831" color={C.ui} />
        <Flow d="M560 866 L560 884" color={C.intel} />
      </svg>
      <figcaption className="muted" style={{ fontSize: 13, marginTop: 8 }}>Everything the target does passes the Rust proxy (or the sandbox tunnel), so the control plane records it without trusting the target. Dashed lines show the direction of data.</figcaption>
    </figure>
  );
}
