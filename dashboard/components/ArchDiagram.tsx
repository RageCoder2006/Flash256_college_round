/** Full system diagram for the landing page. Pure SVG; the dashed flow lines animate unless motion is reduced. */
const C = { go: "#4dd8ff", rs: "#ffb454", ts: "#8f80ff", db: "#35e3ac", ui: "#ff5577", ext: "#8a9cc4" };

function Box({ x, y, w, h, color, title, lines, small }: { x: number; y: number; w: number; h: number; color: string; title: string; lines?: string[]; small?: boolean }) {
  return (
    <g>
      <rect x={x} y={y} width={w} height={h} rx={10} fill="rgba(10,18,40,0.85)" stroke={color} strokeOpacity={0.55} />
      <text x={x + 12} y={y + (small ? 19 : 22)} fill={color} fontFamily="var(--font-jetbrains), monospace" fontSize={small ? 11 : 12.5} fontWeight={600}>{title}</text>
      {lines?.map((l, i) => (
        <text key={l} x={x + 12} y={y + (small ? 35 : 41) + i * 15} fill="#aab7d6" fontFamily="var(--font-figtree), sans-serif" fontSize={small ? 10.5 : 11.5}>{l}</text>
      ))}
    </g>
  );
}

function Group({ x, y, w, h, color, label }: { x: number; y: number; w: number; h: number; color: string; label: string }) {
  return (
    <g>
      <rect x={x} y={y} width={w} height={h} rx={16} fill={color} fillOpacity={0.04} stroke={color} strokeOpacity={0.3} strokeDasharray="3 5" />
      <text x={x + 16} y={y + 22} fill={color} fontFamily="var(--font-jetbrains), monospace" fontSize={11} letterSpacing="2">{label}</text>
    </g>
  );
}

function Flow({ d, color, label, lx, ly, anchor = "middle" }: { d: string; color: string; label?: string; lx?: number; ly?: number; anchor?: "start" | "middle" | "end" }) {
  return (
    <g>
      <path d={d} fill="none" stroke={color} strokeOpacity={0.5} strokeWidth={1.4} markerEnd={`url(#arr-${color.slice(1)})`} />
      <path d={d} fill="none" stroke={color} strokeWidth={1.6} strokeDasharray="2 14" strokeLinecap="round" className="arch-flow" />
      {label && <text x={lx} y={ly} textAnchor={anchor} fill="#8fa0c8" fontFamily="var(--font-jetbrains), monospace" fontSize={10}>{label}</text>}
    </g>
  );
}

export function ArchDiagram() {
  return (
    <figure className="arch-fig">
      <svg viewBox="0 0 1100 800" role="img" aria-labelledby="arch-t arch-d" style={{ width: "100%", height: "auto" }}>
        <title id="arch-t">AVHSOL system architecture</title>
        <desc id="arch-d">A security engineer uses the Next.js dashboard, which talks to the Go control plane. The control plane runs the TypeScript harness and a Rust sandbox, routes all model traffic through the Rust guard proxy to the LLM endpoint, and stores traces in Neo4j and Qdrant, and produces reports.</desc>
        <defs>
          {Object.values(C).map((c) => (
            <marker key={c} id={`arr-${c.slice(1)}`} viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill={c} /></marker>
          ))}
        </defs>

        <Box x={440} y={14} w={220} h={50} color={C.ext} title="Security engineer" lines={["asks, replays, reads the report"]} small />
        <Box x={290} y={104} w={520} h={64} color={C.ui} title="dashboard/ · Next.js 16 · React 19" lines={["Landing · Console · 3D neural graph (react-force-graph-3d)", "run replay command centre · graph chat · report downloads"]} />

        <Group x={30} y={206} w={1040} h={236} color={C.go} label="CONTROL PLANE · GO 1.22 · core/" />
        {[
          ["Campaign engine", "audit → attack → prove", "→ defend → regress"],
          ["Adaptive attacker", "bandit search, model-", "written payloads, shrink"],
          ["Deterministic oracles", "canary at sink, host file", "read, forbidden call"],
          ["Static auditor", "over-privilege, lethal", "trifecta, confused deputy"],
          ["Signed traces", "hash-chained, Ed25519,", "secrets → fingerprints"],
          ["Graph + GraphRAG", "bitemporal ingest, vector", "search, spreading activation"],
          ["Report engine", "JSON skeleton → HTML /", "PDF / MD / JSON / SARIF"],
          ["Hardened API", "role tokens, throttle, audit", "log, security headers"],
        ].map(([t, a, b], i) => (
          <Box key={t} x={50 + (i % 4) * 255} y={240 + Math.floor(i / 4) * 94} w={238} h={78} color={C.go} title={t} lines={[a, b]} small />
        ))}

        <Group x={30} y={478} w={310} h={178} color={C.ts} label="HARNESS · TYPESCRIPT" />
        <Box x={46} y={508} w={278} h={62} color={C.ts} title="Target agent (pi fork)" lines={["simulated-tool scenarios", "or closed-box CLI agents"]} small />
        <Box x={46} y={580} w={278} h={62} color={C.ts} title="Attacker agent (pi)" lines={["plants hidden instructions,", "reads the trace, mutates"]} small />

        <Group x={370} y={478} w={330} h={178} color={C.rs} label="GUARD · RUST" />
        <Box x={386} y={508} w={298} h={62} color={C.rs} title="avhsol-proxy" lines={["LLM-wire proxy: records every", "exchange, strips denied tool calls"]} small />
        <Box x={386} y={580} w={298} h={62} color={C.rs} title="avhsol-guard policy · D1–D7" lines={["fence untrusted · strip hidden · capability", "limits · taint egress · protected paths"]} small />

        <Group x={730} y={478} w={340} h={178} color={C.rs} label="SANDBOX · RUST" />
        <Box x={746} y={508} w={308} h={62} color={C.rs} title="avhsol-sandbox" lines={["Landlock FS + TCP allowlist, seccomp,", "rlimits, no_new_privs · no root needed"]} small />
        <Box x={746} y={580} w={308} h={62} color={C.ext} title="Decoy repo + canary sink" lines={["planted secrets and a local server that", "records any exfiltration attempt"]} small />

        <Box x={30} y={702} w={250} h={70} color={C.ext} title="LLM endpoint" lines={["any OpenAI-compatible /v1", "(your Unsloth model)"]} />
        <Box x={330} y={702} w={230} h={70} color={C.db} title="Neo4j 5" lines={["bitemporal trace graph", "loopback · non-root · pinned"]} />
        <Box x={600} y={702} w={230} h={70} color={C.db} title="Qdrant" lines={["step + payload vectors", "(lexical or semantic embedder)"]} />
        <Box x={870} y={702} w={200} h={70} color={C.ui} title="Security report" lines={["branded, signed digest", "findings · timeline · fixes"]} />

        {/* flows */}
        <Flow d="M550 64 L550 104" color={C.ext} />
        <Flow d="M550 168 L550 206" color={C.ui} label="REST + SSE · bearer role tokens" lx={566} ly={192} anchor="start" />
        <Flow d="M185 442 L185 478" color={C.ts} label="spawn · JSON" lx={197} ly={464} anchor="start" />
        <Flow d="M324 545 L386 545" color={C.rs} label="LLM" lx={355} ly={537} />
        <Flow d="M550 442 L550 478" color={C.rs} label="policy · decisions" lx={562} ly={464} anchor="start" />
        <Flow d="M900 442 L900 478" color={C.rs} label="run closed-box agent" lx={912} ly={464} anchor="start" />
        <Flow d="M746 545 L684 545" color={C.rs} label="model" lx={715} ly={537} />
        <Flow d="M520 656 C 520 690, 160 670, 160 702" color={C.ext} label="upstream to the model" lx={340} ly={684} />
        <Flow d="M355 442 C 355 560, 355 600, 355 702" color={C.db} />
        <Flow d="M715 442 C 715 560, 715 600, 715 702" color={C.db} />
        <Flow d="M1070 380 C 1096 380, 1096 737, 1070 737" color={C.ui} />
      </svg>
      <figcaption className="muted" style={{ fontSize: 13, marginTop: 8 }}>Everything the target does passes the Rust proxy, so the control plane records it without trusting the target. Dashed lines show the direction of data.</figcaption>
    </figure>
  );
}
