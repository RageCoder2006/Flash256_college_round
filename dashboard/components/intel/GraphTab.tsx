"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { Brain, Maximize2, RotateCcw, Search, X } from "lucide-react";
import NeuralGraph, { type NeuralHandle } from "@/components/graph3d/NeuralGraph";
import { get, type IntelItem, type IntelSearch, type IntelSources, type Subgraph } from "@/lib/api";
import { COLORS, fromOverview, linkEnds, nodeColor, type Scene, type SceneNode } from "@/lib/graph3d";
import { ItemDetail } from "./shared";

const LEGEND: [string, string][] = [
  ["Exploited (KEV)", COLORS.breach], ["Critical advisory", "#ff7a45"], ["High advisory", COLORS.amber], ["Medium / other", COLORS.gold],
  ["Research paper", COLORS.teal], ["Data source", COLORS.cyan], ["Attack technique", COLORS.violet], ["Taxonomy id", "#c9a8ff"], ["Package", COLORS.steel],
];

function asItem(n: SceneNode): IntelItem {
  const m = (n.meta ?? {}) as Record<string, unknown>;
  const s = (k: string) => (typeof m[k] === "string" ? (m[k] as string) : undefined);
  return {
    id: n.label, source: s("source") ?? "", kind: s("item_kind") ?? "advisory", title: s("title") ?? n.label, summary: s("summary") ?? "", url: s("url"),
    published: s("published"), severity: s("severity"), cvss: typeof m.cvss === "number" ? m.cvss : undefined, epss: typeof m.epss === "number" ? m.epss : undefined,
    kev: m.kev === true, affects: Array.isArray(m.affects) ? (m.affects as string[]) : undefined, taxon: Array.isArray(m.taxon) ? (m.taxon as string[]) : undefined,
  };
}

export function GraphTab({ meta }: { meta: IntelSources | null }) {
  const [graph, setGraph] = useState<Subgraph | null>(null);
  const [info, setInfo] = useState({ shown: 0, total: 0 });
  const [source, setSource] = useState("");
  const [kind, setKind] = useState("");
  const [kev, setKev] = useState(false);
  const [n, setN] = useState(150);
  const [q, setQ] = useState("");
  const [activation, setActivation] = useState<Map<string, number> | undefined>();
  const [note, setNote] = useState("");
  const [picked, setPicked] = useState<SceneNode | null>(null);
  const [hover, setHover] = useState<SceneNode | null>(null);
  const [size, setSize] = useState({ w: 900, h: 600 });
  const [reduced, setReduced] = useState(false);
  const [err, setErr] = useState("");
  const stage = useRef<HTMLDivElement>(null);
  const handle = useRef<NeuralHandle>(null);

  useEffect(() => { setReduced(window.matchMedia("(prefers-reduced-motion: reduce)").matches); }, []);
  useEffect(() => {
    const el = stage.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setSize({ w: el.clientWidth, h: el.clientHeight }));
    ro.observe(el);
    setSize({ w: el.clientWidth, h: el.clientHeight });
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    let live = true;
    const p = new URLSearchParams({ n: String(n) });
    if (source) p.set("source", source);
    if (kind) p.set("kind", kind);
    if (kev) p.set("kev", "1");
    get<Subgraph & { shown: number; total_matching: number }>(`/api/intel/graph?${p}`)
      .then((g) => { if (live) { setGraph(g); setInfo({ shown: g.shown, total: g.total_matching }); setActivation(undefined); setPicked(null); setErr(""); } })
      .catch((e) => live && setErr(e instanceof Error ? e.message : String(e)));
    return () => { live = false; };
  }, [source, kind, kev, n]);

  const scene: Scene = useMemo(() => (graph ? fromOverview(graph) : { nodes: [], links: [] }), [graph]);
  // the layout needs a moment to settle before the camera can frame it
  useEffect(() => {
    if (!scene.nodes.length) return;
    const t = setTimeout(() => handle.current?.fit(600), 3500);
    return () => clearTimeout(t);
  }, [scene]);

  // Ask the graph: items that match the question light up, and so do the sources, techniques, taxonomy ids and packages around them.
  async function ask(e: React.FormEvent) {
    e.preventDefault();
    const text = q.trim();
    if (!text) { setActivation(undefined); setNote(""); return; }
    try {
      const r = await get<IntelSearch>(`/api/intel/search?q=${encodeURIComponent(text)}`);
      const level = new Map<string, number>();
      const onScreen = new Set(scene.nodes.map((x) => x.id));
      let rank = 0;
      for (const h of r.hits) {
        const id = `intel:${h.source}:${h.id}`;
        if (!onScreen.has(id)) continue;
        level.set(id, Math.max(0.55, 1 - rank * 0.04));
        rank++;
      }
      const spread = new Map(level);
      for (const l of scene.links) {
        const [a, b] = linkEnds(l);
        for (const [x, y] of [[a, b], [b, a]]) {
          const lv = level.get(x);
          if (lv !== undefined && !level.has(y)) spread.set(y, Math.max(spread.get(y) ?? 0, lv * 0.5));
        }
      }
      setActivation(level.size ? spread : undefined);
      setNote(level.size ? `${level.size} records match${r.semantic ? " (by meaning and text)" : ""}. Connected sources, techniques and packages are lit more faintly.` : "None of the records on screen match. Raise the node limit or clear the filters.");
      if (level.size) setTimeout(() => handle.current?.focus([...spread.keys()]), 500);
    } catch (x) {
      setNote(x instanceof Error ? x.message : String(x));
    }
  }

  const neighbours = useMemo(() => {
    if (!picked) return [];
    const byId = new Map(scene.nodes.map((x) => [x.id, x]));
    return scene.links.flatMap((l) => {
      const [a, b] = linkEnds(l);
      if (a !== picked.id && b !== picked.id) return [];
      const o = byId.get(a === picked.id ? b : a);
      return o ? [{ o, type: l.type }] : [];
    });
  }, [picked, scene]);

  const sources = (meta?.sources ?? []).filter((s) => s.role !== "enricher");
  const shown = hover && hover.id !== picked?.id ? hover : null;

  return (
    <div>
      <div className="ti-filters" style={{ marginBottom: 10 }}>
        <form className="ti-search" onSubmit={ask} style={{ flex: 1, minWidth: 280 }}>
          <Brain size={16} aria-hidden="true" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Ask the graph: which records are about tool poisoning in MCP servers?" aria-label="Question for the threat intelligence graph" />
          <button className="btn">Light up</button>
          {activation && <button type="button" className="btn ghost" onClick={() => { setActivation(undefined); setNote(""); setQ(""); handle.current?.fit(); }}><RotateCcw size={14} /> Reset</button>}
        </form>
        <select value={source} onChange={(e) => setSource(e.target.value)} aria-label="Source"><option value="">All sources</option>{sources.map((s) => <option key={s.name} value={s.name}>{s.name}</option>)}</select>
        <select value={kind} onChange={(e) => setKind(e.target.value)} aria-label="Kind"><option value="">All kinds</option><option value="advisory">Advisories</option><option value="cve">CVEs</option><option value="paper">Papers</option></select>
        <select value={n} onChange={(e) => setN(+e.target.value)} aria-label="How many records"><option value={60}>60 records</option><option value={150}>150 records</option><option value={300}>300 records</option></select>
        <label className="ti-check"><input type="checkbox" checked={kev} onChange={(e) => setKev(e.target.checked)} /> Exploited only</label>
      </div>
      {note && <div className="ti-msg" role="status">{note}</div>}
      {err && <div className="ti-msg bad">{err}</div>}
      <div className="graph-stage cc-stage" ref={stage} style={{ height: "calc(100vh - 250px)" }}>
        <NeuralGraph ref={handle} scene={scene} width={size.w} height={size.h} activation={activation} selected={picked?.id} reduced={reduced} onNodeHover={setHover} onNodeClick={setPicked} />
        <div className="cc-scan" aria-hidden="true" />
        <i className="cc-corner tl" /><i className="cc-corner tr" /><i className="cc-corner bl" /><i className="cc-corner br" />
        <div className="hud tl glass cc-legend">
          <div className="cc-title" style={{ marginBottom: 4 }}>Threat intelligence knowledge graph</div>
          {LEGEND.map(([l, c]) => <div key={l} className="legend-row"><span className="legend-dot" style={{ color: c, background: c }} />{l}</div>)}
          <div className="muted" style={{ marginTop: 6 }}>Showing {info.shown} of {info.total} matching records</div>
        </div>
        {shown && <div className="cc-hover glass"><b>{shown.kind}</b> {shown.label}{shown.meta?.title ? ` · ${String(shown.meta.title).slice(0, 90)}` : ""}</div>}
        <div className="hud tr cc-tools-top" style={{ right: picked ? 392 : 14 }}>
          <button className="btn ghost" onClick={() => handle.current?.fit()} aria-label="Fit graph to view"><Maximize2 size={14} /> Fit</button>
        </div>
        {picked && (
          <aside className="cc-dock glass" aria-label="Selected node">
            <div className="cc-tabs"><button className="on" style={{ cursor: "default" }}>{picked.kind === "intel" ? "Record" : picked.kind}</button><button className="cc-min" onClick={() => setPicked(null)} aria-label="Close panel"><X size={15} /></button></div>
            <div className="cc-dock-body">
              {picked.kind === "intel" ? <ItemDetail it={asItem(picked)} /> : (
                <div className="ins">
                  <div className="ins-head"><i style={{ background: nodeColor(picked), boxShadow: `0 0 10px ${nodeColor(picked)}` }} /><div><small>{picked.kind}</small><h3>{picked.label}</h3></div></div>
                  {picked.kind === "source" && <p className="muted" style={{ fontSize: 13 }}>A data source. The records linked below came from it.</p>}
                  {picked.kind === "taxon" && <p className="muted" style={{ fontSize: 13 }}>{String(picked.meta?.family ?? "")} identifier. Linked techniques map to it.</p>}
                  {picked.kind === "technique" && <p className="muted" style={{ fontSize: 13 }}>An attack technique AVHSOL tests. Linked records describe attacks of this kind.</p>}
                </div>
              )}
              <div className="cc-title" style={{ marginTop: 14 }}>Connections · {neighbours.length}</div>
              <div className="ins-links">
                {neighbours.slice(0, 40).map(({ o, type }) => (
                  <button key={o.id + type} onClick={() => { setPicked(o); handle.current?.focusNode(o.id); }}>
                    <i style={{ background: nodeColor(o) }} /><span>{type.toLowerCase().replace(/_/g, " ")}</span><b>{o.label || o.id}</b>
                  </button>
                ))}
              </div>
            </div>
          </aside>
        )}
        {!scene.nodes.length && !err && (
          <div className="cc-hover glass" style={{ top: "45%" }}><Search size={14} style={{ verticalAlign: -2 }} /> No records to draw. Sync the data sources first.</div>
        )}
      </div>
    </div>
  );
}
