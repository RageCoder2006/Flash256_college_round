import type { GNode, Subgraph } from "@/lib/api";

const LANE: Record<string, number> = { payload: 0, resource: 0, secret: 0, tool_result: 1, tool_call: 2, user_turn: 2, guard: 3 };
const Y = [34, 104, 178, 250];
const W = 92;

function colour(n: GNode) {
  if (n.flag === "blocked") return "var(--held)";
  if (n.flag === "untrusted") return "var(--breach)";
  if (n.flag === "leak") return "var(--caution)";
  return "var(--ink-3)";
}

/**
 * The causal story of one episode. Results on the second row, calls on the third, guard decisions
 * below. Red dashed arcs are provenance: this call happened after, and because of, that untrusted read.
 * A text version of the same path sits next to it.
 */
export function CausalGraph({ g }: { g: Subgraph }) {
  const steps = g.nodes.filter((n) => n.kind === "user_turn" || (LANE[n.kind] !== undefined && LANE[n.kind] >= 1)).sort((a, b) => a.seq - b.seq);
  const pos = new Map<string, { x: number; y: number }>();
  const X0 = 120; // left gutter holds the lane labels
  steps.forEach((n, i) => pos.set(n.id, { x: X0 + i * W, y: Y[LANE[n.kind] ?? 2] }));
  for (const n of g.nodes) {
    if (pos.has(n.id)) continue;
    const linked = g.edges.filter((e) => e.from === n.id || e.to === n.id).map((e) => pos.get(e.from === n.id ? e.to : e.from)).filter(Boolean) as { x: number; y: number }[];
    const x = linked.length ? linked.reduce((s, p) => s + p.x, 0) / linked.length : X0;
    pos.set(n.id, { x: n.kind === "payload" ? Math.max(X0, x - W) : x, y: Y[0] });
  }
  const width = Math.max(520, steps.length * W + X0 + 40);
  const edge = (e: { from: string; to: string; type: string }, i: number) => {
    const a = pos.get(e.from), b = pos.get(e.to);
    if (!a || !b || e.type === "NEXT") return null;
    const tainted = e.type === "TAINTED_BY";
    const stroke = tainted ? "var(--breach)" : e.type === "EVALUATED" ? "var(--held)" : e.type === "LEAKED" || e.type === "EXPOSED" ? "var(--caution)" : "var(--line)";
    const mid = (a.x + b.x) / 2;
    const bend = tainted ? Math.min(60, 14 + Math.abs(a.x - b.x) / 5) : 0;
    const d = `M${a.x},${a.y - 14} Q${mid},${Math.min(a.y, b.y) - 14 - bend} ${b.x},${b.y + 14}`;
    return <path key={i} d={tainted ? d : `M${a.x},${a.y - 14} L${b.x},${b.y + 14}`} fill="none" stroke={stroke} strokeWidth={tainted ? 1.6 : 1.2} strokeDasharray={tainted ? "5 3" : undefined} opacity={0.9}><title>{e.type.toLowerCase().replace("_", " ")}</title></path>;
  };
  const label = g.nodes.length + " nodes: " + steps.map((n) => n.label).slice(0, 12).join(", ");
  return (
    <div style={{ overflowX: "auto" }}>
      <svg role="img" aria-label={"Causal graph. " + label} width={width} height={300} style={{ display: "block" }}>
        {[["artifacts", 0], ["results", 1], ["calls", 2], ["guard", 3]].map(([t, i]) => (
          <text key={String(t)} x={4} y={Y[i as number] + 4} fontSize={10.5} fill="var(--ink-3)" style={{ textTransform: "uppercase", letterSpacing: "0.04em" }}>{t}</text>
        ))}
        {g.edges.map(edge)}
        {g.nodes.map((n) => {
          const p = pos.get(n.id);
          if (!p) return null;
          const c = colour(n);
          return (
            <g key={n.id} transform={`translate(${p.x - 38},${p.y - 14})`}>
              <rect width={76} height={28} rx={6} fill="var(--surface)" stroke={c} strokeWidth={n.flag ? 2 : 1.2} />
              <text x={38} y={18} textAnchor="middle" fontSize={11} fill="var(--ink)">{n.label.length > 11 ? n.label.slice(0, 10) + "…" : n.label}</text>
              <title>{`#${n.seq} ${n.kind}: ${n.label}`}</title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
