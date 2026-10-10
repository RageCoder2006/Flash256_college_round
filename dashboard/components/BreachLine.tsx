import type { Node } from "@/lib/api";

/**
 * A breach line: payload -> ingest -> tool calls -> egress -> outcome.
 * Unguarded runs are red end to end. A guarded run turns teal and the chain snaps
 * (with the rule id) at the exact call the guard stopped.
 */
export function BreachLine({ nodes }: { nodes: Node[] }) {
  const cutAt = nodes.findIndex((n) => n.blocked);
  const leaked = nodes.some((n) => n.kind === "outcome" && n.label === "data leaked");
  return (
    <div className="chain" role="img" aria-label={nodes.map((n) => n.label + (n.blocked ? " (blocked by guard)" : "")).join(", then ")}>
      {nodes.map((n, i) => {
        const afterCut = cutAt >= 0 && i > cutAt;
        const tone = afterCut ? "tone-plain" : cutAt >= 0 ? "tone-held" : leaked ? "tone-breach" : "tone-plain";
        const isOutcome = n.kind === "outcome";
        return (
          <span key={i} style={{ display: "inline-flex", alignItems: "center" }}>
            {i > 0 &&
              (i - 1 === cutAt ? (
                <span className="seam cut" aria-hidden="true"><i>×</i></span>
              ) : (
                <span className={`seam ${afterCut ? "tone-plain" : tone}`} aria-hidden="true" />
              ))}
            <span className={`link ${tone}`}>
              <span className={`chip k-${n.kind}${afterCut ? " ghost" : ""}${isOutcome ? " outcome" : ""}`} title={n.reason || n.label}>
                {n.label}
              </span>
              {n.blocked && n.rule && <span className="rule">blocked · {n.rule}</span>}
            </span>
          </span>
        );
      })}
    </div>
  );
}
