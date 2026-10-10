"use client";
import { useEffect, useRef, useState } from "react";
import { animate } from "animejs";
import { Play } from "lucide-react";
import type { Note, PathStep, TechniqueStat } from "@/lib/api";
import { COLORS, linkEnds, nodeColor } from "@/lib/graph3d";
import type { Scene, SceneNode } from "@/lib/graph3d";
import type { Telemetry } from "@/lib/telemetry";

const RISK_COLOR: Record<string, string> = { info: "#7fa0d8", watch: COLORS.amber, danger: COLORS.breach, blocked: COLORS.cyan };

/** Counts up to the value; instant when motion is reduced. */
function Count({ v, reduced }: { v: number; reduced: boolean }) {
  const ref = useRef<HTMLSpanElement>(null);
  const last = useRef(0);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (reduced) { el.textContent = String(v); return; }
    const o = { n: last.current };
    animate(o, { n: v, duration: 500, ease: "outQuad", onUpdate: () => { el.textContent = String(Math.round(o.n)); } });
    last.current = v;
  }, [v, reduced]);
  return <span ref={ref}>{v}</span>;
}

export function Telemetry({ t, reduced }: { t: Telemetry; reduced: boolean }) {
  const cells: [string, number, string][] = [
    ["Steps", t.steps, "#9bb4e8"], ["Tool calls", t.calls, COLORS.blue], ["Untrusted reads", t.untrusted, COLORS.amber],
    ["Steered calls", t.tainted, COLORS.breach], ["Secrets touched", t.secrets, COLORS.gold], ["Guard denials", t.denied, COLORS.cyan],
  ];
  const level = t.threat > 66 ? "CRITICAL" : t.threat > 33 ? "ELEVATED" : "NOMINAL";
  const lc = t.threat > 66 ? COLORS.breach : t.threat > 33 ? COLORS.amber : COLORS.held;
  return (
    <div className="cc-panel">
      <div className="cc-title">Telemetry</div>
      <div className="cc-cells">
        {cells.map(([l, v, c]) => (
          <div key={l} className="cc-cell" style={{ ["--c" as string]: c }}>
            <b><Count v={v} reduced={reduced} /></b><span>{l}</span>
          </div>
        ))}
      </div>
      <div className="cc-threat">
        <div className="cc-row"><span>Threat level</span><b style={{ color: lc }}>{level}</b></div>
        <div className="act-bar"><i style={{ width: `${t.threat}%`, background: lc, boxShadow: `0 0 12px ${lc}` }} /></div>
      </div>
      <div className="cc-title" style={{ marginTop: 12 }}>Attack chain</div>
      <ol className="cc-chain">
        {t.chain.map((c) => (
          <li key={c.key} className={c.hit ? "hit" : ""} style={{ ["--c" as string]: c.key === "guard" ? COLORS.cyan : c.key === "breach" ? COLORS.breach : COLORS.amber }}>
            <i />{c.label}
          </li>
        ))}
      </ol>
      {t.tools.length > 0 && <div className="cc-tools">{t.tools.map((x) => <code key={x}>{x}</code>)}</div>}
    </div>
  );
}

export function Feed({ path, notes, upto, onPick }: { path: PathStep[]; notes?: Record<string, Note>; upto: number; onPick: (seq: number) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const rows = path.filter((p) => p.seq <= upto);
  useEffect(() => { ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" }); }, [rows.length]);
  return (
    <div className="cc-panel cc-feed">
      <div className="cc-title">Event feed</div>
      <div className="cc-feed-list" ref={ref}>
        {rows.map((p) => {
          const n = notes?.[String(p.seq)];
          const risk = n?.risk ?? "info";
          return (
            <button key={p.seq} className="cc-ev" onClick={() => onPick(p.seq)} style={{ ["--c" as string]: RISK_COLOR[risk] }}>
              <code>{String(p.seq).padStart(2, "0")}</code>
              <span><b>{p.type.replace("_", " ")}{p.name ? ` · ${p.name}` : ""}</b>{n ? ` — ${n.text}` : ""}</span>
            </button>
          );
        })}
        {!rows.length && <span className="muted">Waiting for the first event…</span>}
      </div>
    </div>
  );
}

export function NowCard({ step, note, source, loading, reduced }: { step?: PathStep; note?: Note; source?: string; loading: boolean; reduced: boolean }) {
  const [shown, setShown] = useState("");
  const text = note?.text ?? "";
  useEffect(() => {
    if (reduced) { setShown(text); return; }
    setShown("");
    let i = 0;
    const t = setInterval(() => { i += 2; setShown(text.slice(0, i)); if (i >= text.length) clearInterval(t); }, 14);
    return () => clearInterval(t);
  }, [text, reduced]);
  const risk = note?.risk ?? "info";
  return (
    <div className="cc-now" style={{ ["--c" as string]: RISK_COLOR[risk] }}>
      <div className="cc-row">
        <span className="cc-title" style={{ margin: 0 }}>{step ? `Step ${step.seq} · ${step.type.replace("_", " ")}` : "Standing by"}</span>
        <span className="cc-badge">{loading ? "analysing…" : source === "llm" ? "LLM-narrated from the graph" : "rule-based"}</span>
      </div>
      {step && (step.name || step.args) && <code className="cc-cmd">$ {step.name} {step.args}</code>}
      <p>{step ? shown || (loading ? "…" : "") : "Press play to watch the agent act."}</p>
    </div>
  );
}

function Row({ k, v }: { k: string; v?: React.ReactNode }) {
  if (v === undefined || v === null || v === "") return null;
  return <div className="ins-row"><span>{k}</span><b>{v}</b></div>;
}

export function Inspector({ node, scene, paths, notes, techniques, onPick, onReplay }: {
  node: SceneNode | null; scene: Scene; paths: Record<string, PathStep[]>; notes: Record<string, Record<string, Note>>;
  techniques: TechniqueStat[]; onPick: (id: string) => void; onReplay: (ep: string) => void;
}) {
  if (!node) return <div className="ins-empty muted">Click any node to inspect it: what it is, what it connects to, and what happened there.</div>;
  const m = node.meta ?? {};
  const step = node.ep ? paths[node.ep]?.find((p) => p.seq === node.seq) : undefined;
  const note = node.ep && node.seq !== undefined ? notes[node.ep]?.[String(node.seq)] : undefined;
  const byId = new Map(scene.nodes.map((n) => [n.id, n]));
  const neighbours = scene.links.flatMap((l) => {
    const [a, b] = linkEnds(l);
    if (a !== node.id && b !== node.id) return [];
    const o = byId.get(a === node.id ? b : a);
    return o ? [{ o, type: l.type, out: a === node.id }] : [];
  });
  const tech = node.kind === "technique" ? techniques.find((t) => t.technique === node.label) : undefined;
  const epId = node.kind === "episode" ? node.id.replace(/^ep:/, "") : undefined;
  return (
    <div className="ins">
      <div className="ins-head"><i style={{ background: nodeColor(node), boxShadow: `0 0 10px ${nodeColor(node)}` }} /><div><small>{node.kind.replace("_", " ")}</small><h3>{node.label || node.id}</h3></div></div>
      {note && <p className="ins-note" style={{ borderColor: RISK_COLOR[note.risk] }}>{note.text}</p>}
      {epId && <>
        <Row k="Outcome" v={m.achieved ? "Exploit landed" : "Held"} />
        <Row k="Kind" v={String(m.episode_kind ?? "")} />
        <Row k="Scenario" v={String(m.scenario ?? "")} />
        <Row k="Target" v={String(m.target ?? "")} />
        <Row k="Guard" v={String(m.guard ?? "")} />
        <Row k="Steps" v={String(m.steps ?? "")} />
        <button className="btn" style={{ marginTop: 10 }} onClick={() => onReplay(epId)}><Play size={14} /> Replay this run</button>
      </>}
      {step && <>
        <Row k="Step" v={`#${step.seq} · ${step.type.replace("_", " ")}`} />
        <Row k="Tool" v={step.name} />
        <Row k="Arguments" v={step.args && <code className="ins-code">{step.args}</code>} />
        <Row k="Content" v={step.content && <code className="ins-code">{step.content.slice(0, 400)}</code>} />
        <Row k="Source" v={step.source ? `untrusted · ${step.source}` : undefined} />
        <Row k="Guard" v={step.decision && `${step.decision.toUpperCase()} ${step.rules?.join("+") ?? ""}`} />
        <Row k="Steered by" v={step.tainted_by !== undefined && step.tainted_by !== null ? `step ${step.tainted_by}` : undefined} />
        <Row k="Secrets" v={step.secrets?.join(", ")} />
      </>}
      {node.kind === "payload" && <Row k="Payload text" v={<code className="ins-code">{String(m.text ?? "").slice(0, 500)}</code>} />}
      {tech && <>
        <Row k="Episodes" v={tech.episodes} />
        <Row k="Succeeded" v={`${tech.succeeded} (${Math.round(tech.rate * 100)}%)`} />
        <Row k="Stopped by" v={tech.stopped_by?.join(", ")} />
      </>}
      {node.flag && <Row k="Flag" v={node.flag} />}
      <div className="cc-title" style={{ marginTop: 14 }}>Connections · {neighbours.length}</div>
      <div className="ins-links">
        {neighbours.slice(0, 40).map(({ o, type, out }) => (
          <button key={o.id + type} onClick={() => onPick(o.id)}>
            <i style={{ background: nodeColor(o) }} />
            <span>{out ? "→" : "←"} {type.toLowerCase().replace("_", " ")}</span>
            <b>{o.label || o.id}</b>
          </button>
        ))}
      </div>
    </div>
  );
}
