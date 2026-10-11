import type { Node } from "@/lib/api";

const PHASE: Record<Node["kind"], string> = { surface: "Surface", ingest: "Ingest", tool: "Call", egress: "Egress", outcome: "Outcome" };

function Arrow({ cls }: { cls: string }) {
  return (
    <span className={`farrow ${cls}`} aria-hidden="true">
      <svg viewBox="0 0 34 14" preserveAspectRatio="none">
        <line x1="2" y1="7" x2="26" y2="7" stroke="currentColor" strokeWidth="1.5" />
        <path d="M24 2.5 L31 7 L24 11.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="miter" />
      </svg>
    </span>
  );
}

/**
 * Exploit travel as a flowchart: surface -> ingest -> call -> egress -> outcome.
 * Unguarded runs flow into a crimson breach terminal. A guarded run turns mint and the chain
 * is severed at an explicit INTERCEPT gate carrying the rule that stopped it.
 */
export function BreachLine({ nodes }: { nodes: Node[] }) {
  const cutAt = nodes.findIndex((n) => n.blocked);
  const leaked = nodes.some((n) => n.kind === "outcome" && n.label === "data leaked");
  const label = nodes.map((n) => n.label + (n.blocked ? " (blocked by guard)" : "")).join(", then ");
  return (
    <div className="flow" role="img" aria-label={label} tabIndex={0}>
      {nodes.map((n, i) => {
        const afterCut = cutAt >= 0 && i > cutAt;
        const tone = afterCut ? "tone-plain" : cutAt >= 0 ? "tone-held" : leaked ? "tone-breach" : "tone-plain";
        const isOutcome = n.kind === "outcome";
        return (
          <div key={i} style={{ display: "flex", alignItems: "stretch" }}>
            {i > 0 && <Arrow cls={i - 1 === cutAt ? "cut" : afterCut ? "dead" : leaked && cutAt < 0 ? "live tone-breach" : "live"} />}
            <div className={`fnode ${tone}${afterCut ? " ghost" : ""}`} title={n.reason || n.label}>
              <div className="ph"><span>{PHASE[n.kind] ?? n.kind}</span><i>{String(i + 1).padStart(2, "0")}</i></div>
              <div className="op">{n.label}</div>
              {isOutcome && !afterCut && cutAt < 0 && leaked && <div className="ph" style={{ color: "var(--breach)" }}>Exfiltrated</div>}
            </div>
            {i === cutAt && (
              <>
                <Arrow cls="cut" />
                <div className="fnode gate">
                  <div className="ph"><span>Intercept</span><i>Defense engaged</i></div>
                  <div className="op">GATE: [{n.rule || "GUARD_BLOCK"}]</div>
                  <div className="ph" style={{ color: "var(--ink-3)" }}>Chain severed</div>
                </div>
              </>
            )}
          </div>
        );
      })}
      {cutAt < 0 && leaked && (
        <div style={{ display: "flex", alignItems: "stretch" }}>
          <Arrow cls="live tone-breach" />
          <div className="fnode breach">
            <div className="ph"><span>Breach</span><i>Terminal</i></div>
            <div className="op">EXPLOIT CONFIRMED · CANARY EXFILTRATED</div>
          </div>
        </div>
      )}
    </div>
  );
}
