"use client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { animate } from "animejs";
import { Brain, ChevronRight, Maximize2, MessageSquare, Pause, Play, RotateCcw, ScanSearch, Send, SkipBack, X } from "lucide-react";
import NeuralGraph, { type NeuralHandle } from "@/components/graph3d/NeuralGraph";
import { Feed, Inspector, NowCard, Telemetry } from "@/components/graph3d/Panels";
import { ApiError, get, post, type Activation, type EpisodeRow, type GraphAnswer, type Narration, type PathStep, type Subgraph, type TechniqueStat } from "@/lib/api";
import { useFetch } from "@/lib/use";
import { telemetry } from "@/lib/telemetry";
import {
  COLORS, emptyScene, fromOverview, layoutRun, linkEnds, mergeEpisode, releaseRun, runNodeIds, runOverview,
  type Scene, type SceneNode,
} from "@/lib/graph3d";

interface Msg { who: "user" | "bot" | "sys"; text: string }

const SUGGEST = [
  "Which attacks stole the credentials?",
  "What did the guard stop?",
  "Show attacks that used a hidden instruction",
  "What did the agent read before sending data out?",
];

export default function NeuralGraphPage() {
  const status = useFetch<{ configured: boolean }>("/api/graph/status");
  const ready = !!status.data?.configured;
  const overview = useFetch<Subgraph>(ready ? "/api/graph/overview?episodes=60" : null);
  const eps = useFetch<EpisodeRow[]>(ready ? "/api/graph/episodes?n=60" : null);
  const techs = useFetch<TechniqueStat[]>(ready ? "/api/graph/techniques" : null);

  const [scene, setScene] = useState<Scene>(emptyScene());
  const [hover, setHover] = useState<SceneNode | null>(null);
  const [picked, setPicked] = useState<SceneNode | null>(null);
  const [activation, setActivation] = useState<Map<string, number> | undefined>();
  const [msgs, setMsgs] = useState<Msg[]>([{ who: "sys", text: "Ask about what the agents did. The parts of the graph the answer draws on light up." }]);
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [replayEp, setReplayEp] = useState<string | null>(null);
  const [paths, setPaths] = useState<Record<string, PathStep[]>>({});
  const [narr, setNarr] = useState<Record<string, Narration>>({});
  const [narrating, setNarrating] = useState(false);
  const [cursor, setCursor] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [size, setSize] = useState({ w: 900, h: 600 });
  const [reduced, setReduced] = useState(false);
  const [dockOpen, setDockOpen] = useState(false);
  const [tab, setTab] = useState<"inspect" | "ask">("ask");
  const stage = useRef<HTMLDivElement>(null);
  const handle = useRef<NeuralHandle>(null);
  const logRef = useRef<HTMLDivElement>(null);
  const barRef = useRef<HTMLElement>(null);
  const sceneRef = useRef(scene);
  sceneRef.current = scene;
  const loadedRef = useRef(new Set<string>());

  useEffect(() => { setReduced(window.matchMedia("(prefers-reduced-motion: reduce)").matches); }, []);
  useEffect(() => { if (overview.data) setScene(fromOverview(overview.data)); }, [overview.data]);

  useEffect(() => {
    const el = stage.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setSize({ w: el.clientWidth, h: el.clientHeight }));
    ro.observe(el);
    setSize({ w: el.clientWidth, h: el.clientHeight });
    return () => ro.disconnect();
  }, []);

  useEffect(() => { logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: "smooth" }); }, [msgs]);

  const say = (m: Msg) => setMsgs((x) => [...x, m]);

  const ensureEpisode = useCallback(async (id: string): Promise<Scene> => {
    if (loadedRef.current.has(id)) return sceneRef.current;
    loadedRef.current.add(id);
    try {
      const [sub, p] = await Promise.all([get<Subgraph>(`/api/graph/episodes/${id}/subgraph`), get<PathStep[]>(`/api/graph/episodes/${id}/path`)]);
      const next = mergeEpisode(sceneRef.current, id, sub);
      sceneRef.current = next;
      setScene(next);
      setPaths((x) => ({ ...x, [id]: p }));
      return next;
    } catch (e) {
      loadedRef.current.delete(id);
      throw e;
    }
  }, []);

  // ---- brain activation from a question ----
  async function ask(text: string) {
    const question = text.trim();
    if (!question || busy) return;
    setQ("");
    setBusy(true);
    say({ who: "user", text: question });
    if (replayEp) stopReplay();
    try {
      let ans: GraphAnswer;
      try {
        ans = await post<GraphAnswer>("/api/graph/ask", { question });
      } catch (e) {
        if (e instanceof ApiError && (e.status === 403 || e.status === 503)) {
          ans = await post<GraphAnswer>("/api/graph/activate", { text: question });
          say({ who: "sys", text: "The model is not available to this session, so this shows retrieval only." });
        } else throw e;
      }
      const act: Activation[] = ans.activation ?? [];
      const wanted = new Set<string>(ans.episodes ?? []);
      for (const a of act) {
        const i = a.id.indexOf("#");
        if (i > 0) wanted.add(a.id.slice(0, i));
      }
      for (const ep of [...wanted].slice(0, 8)) await ensureEpisode(ep).catch(() => undefined);
      const m = new Map(act.map((a) => [a.id, a.level]));
      setActivation(m.size ? m : undefined);
      say({ who: "bot", text: ans.answer || (m.size ? `${m.size} nodes activated.` : "Nothing in the graph matched.") });
      if (m.size) setTimeout(() => handle.current?.focus([...m.keys()]), 700);
    } catch (e) {
      say({ who: "sys", text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  }

  // ---- run replay ----
  async function loadNarration(id: string) {
    if (narr[id]) return;
    setNarrating(true);
    try {
      let n: Narration;
      try {
        n = await post<Narration>(`/api/graph/episodes/${id}/narrate`, {});
      } catch (e) {
        if (e instanceof ApiError && (e.status === 403 || e.status === 503)) n = await get<Narration>(`/api/graph/episodes/${id}/narrate`);
        else throw e;
      }
      setNarr((x) => ({ ...x, [id]: n }));
    } catch {
      /* the replay still works without the notes */
    } finally {
      setNarrating(false);
    }
  }

  async function startReplay(id: string) {
    setActivation(undefined);
    setPlaying(false);
    try {
      const next = await ensureEpisode(id);
      const steps = layoutRun(next, id);
      setScene({ nodes: next.nodes, links: next.links });
      setReplayEp(id);
      setCursor(0);
      setPicked(null);
      void loadNarration(id);
      handle.current?.reheat();
      setTimeout(() => handle.current?.overview(runOverview(steps.length), 1000), 250);
      setTimeout(() => setPlaying(true), 1500);
    } catch (e) {
      say({ who: "sys", text: e instanceof Error ? e.message : String(e) });
    }
  }

  function stopReplay() {
    if (replayEp) {
      releaseRun(sceneRef.current, replayEp);
      handle.current?.reheat();
    }
    setReplayEp(null);
    setPlaying(false);
    setTimeout(() => handle.current?.fit(), 600);
  }

  const path = replayEp ? paths[replayEp] ?? [] : [];
  const seqs = useMemo(() => (replayEp ? scene.nodes.filter((n) => n.ep === replayEp).map((n) => n.seq ?? 0).sort((a, b) => a - b) : []), [scene.nodes, replayEp]);

  useEffect(() => {
    if (!playing || !replayEp) return;
    if (cursor >= seqs.length) { setPlaying(false); return; }
    const t = setTimeout(() => setCursor((c) => c + 1), 1500 / speed);
    return () => clearTimeout(t);
  }, [playing, cursor, speed, replayEp, seqs.length]);

  const visible = useMemo(() => {
    if (!replayEp) return undefined;
    const run = runNodeIds(scene, replayEp);
    const shown = new Set<string>();
    const upto = seqs[Math.max(0, cursor - 1)];
    for (const n of scene.nodes) {
      if (!run.has(n.id)) continue;
      if (n.ep === replayEp) { if (cursor > 0 && (n.seq ?? 0) <= (upto ?? -1)) shown.add(n.id); } else shown.add(n.id);
    }
    for (const n of scene.nodes) {
      if (!run.has(n.id) || n.ep === replayEp || ["episode", "technique", "payload", "defense"].includes(n.kind)) continue;
      const touched = scene.links.some((l) => { const [a, b] = linkEnds(l); return (a === n.id && shown.has(b)) || (b === n.id && shown.has(a)); });
      if (!touched) shown.delete(n.id);
    }
    return shown;
  }, [scene, replayEp, cursor, seqs]);

  const curSeq = replayEp && cursor > 0 ? seqs[cursor - 1] : undefined;
  const curStep = curSeq !== undefined ? path.find((p) => p.seq === curSeq) : undefined;
  const curNode = curSeq !== undefined ? scene.nodes.find((n) => n.ep === replayEp && n.seq === curSeq) : undefined;
  const narration = replayEp ? narr[replayEp] : undefined;
  const note = curSeq !== undefined ? narration?.steps?.[String(curSeq)] : undefined;
  const epNode = replayEp ? scene.nodes.find((n) => n.id === "ep:" + replayEp) : undefined;
  const tele = useMemo(() => telemetry(path, curSeq ?? -1, !!epNode?.meta?.achieved), [path, curSeq, epNode]);

  // chase camera: follow the step that just happened
  useEffect(() => {
    if (curNode && playing) handle.current?.chase(curNode.id, reduced ? 0 : 900 / speed);
  }, [curNode?.id, playing]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (curNode && !playing) handle.current?.chase(curNode.id, 600);
  }, [cursor]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!barRef.current || reduced) return;
    animate(barRef.current, { width: `${(cursor / Math.max(1, seqs.length)) * 100}%`, duration: 400, ease: "outQuad" });
  }, [cursor, seqs.length, reduced]);

  const top = useMemo(() => {
    if (!activation) return [];
    return [...activation.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([id, v]) => ({ id, v, n: scene.nodes.find((x) => x.id === id) }));
  }, [activation, scene.nodes]);

  const pick = useCallback((n: SceneNode) => {
    setPicked(n);
    setTab("inspect");
    setDockOpen(true);
    if (n.ep && !replayEp) void ensureEpisode(n.ep).catch(() => undefined);
    if (n.ep) void loadNarration(n.ep);
  }, [replayEp]); // eslint-disable-line react-hooks/exhaustive-deps

  const pickId = (id: string) => {
    const n = sceneRef.current.nodes.find((x) => x.id === id);
    if (n) { pick(n); if (!replayEp) handle.current?.focusNode(id); }
  };

  if (status.data && !status.data.configured) {
    return <div className="card"><h2>Neural graph</h2><p className="muted">Neo4j is not configured. Start the stack with <code>scripts/stack.sh</code>, then run an attack with <code>-graph</code>.</p></div>;
  }
  const episodes = (eps.data ?? []).slice(0, 40);
  const hovered = hover && hover.id !== picked?.id ? hover : null;

  return (
    <div className="cc-page">
      <div className="cc-head">
        <div><h1>Neural graph</h1><p className="muted">Click a run to replay it as a mission; click any node to inspect it; ask a question to light up what the answer draws on.</p></div>
      </div>

      <div className="cc-layout">
      <div className={`graph-stage cc-stage${replayEp ? " live" : ""}`} ref={stage}>
        <NeuralGraph ref={handle} scene={scene} width={size.w} height={size.h} activation={activation} visible={visible}
          selected={picked?.id} reduced={reduced} onNodeHover={setHover} onNodeClick={pick} />
        <div className="cc-scan" aria-hidden="true" />
        <i className="cc-corner tl" /><i className="cc-corner tr" /><i className="cc-corner bl" /><i className="cc-corner br" />

        {/* legend + hover readout */}
        <div className="hud tl glass cc-legend" hidden={!!replayEp}>
          {([["Exploit landed", COLORS.breach], ["Held", COLORS.held], ["Benign task", COLORS.blue], ["Technique", COLORS.violet], ["Payload", COLORS.amber], ["Defense", COLORS.cyan], ["Secret", COLORS.gold]] as const).map(([l, c]) => (
            <div key={l} className="legend-row"><span className="legend-dot" style={{ color: c, background: c }} />{l}</div>
          ))}
          <div className="muted" style={{ marginTop: 6 }}>{scene.nodes.length} nodes · {scene.links.length} links</div>
        </div>
        {hovered && <div className="cc-hover glass"><b>{hovered.kind.replace("_", " ")}</b> {hovered.label}</div>}

        {/* left column: mission telemetry */}
        {replayEp && (
          <div className="cc-left">
            <div className="cc-panel cc-mission">
              <div className="cc-title">Mission · {replayEp}</div>
              <p>{narration?.summary ?? (narrating ? "Analysing the run with the graph…" : "")}</p>
              <div className="cc-row"><span>{String(epNode?.meta?.scenario ?? "")} · guard {String(epNode?.meta?.guard ?? "")}</span><b style={{ color: epNode?.meta?.achieved ? COLORS.breach : COLORS.held }}>{epNode?.meta?.achieved ? "EXPLOIT LANDED" : "HELD"}</b></div>
            </div>
            <Telemetry t={tele} reduced={reduced} />
            <Feed path={path} notes={narration?.steps} upto={curSeq ?? -1} onPick={(s) => { setPlaying(false); setCursor(seqs.indexOf(s) + 1); }} />
          </div>
        )}

        {/* bottom: transport + narration */}
        {replayEp && (
          <div className="cc-bottom">
            <NowCard step={curStep} note={note} source={narration?.source} loading={narrating && !narration} reduced={reduced} />
            <div className="cc-transport glass">
              <button className="btn ghost" onClick={() => { setPlaying(false); setCursor(0); }} aria-label="Restart"><SkipBack size={14} /></button>
              <button className="btn ghost" onClick={() => { if (cursor >= seqs.length) setCursor(0); setPlaying((p) => !p); }} aria-label={playing ? "Pause" : "Play"}>{playing ? <Pause size={14} /> : <Play size={14} />}</button>
              <div style={{ flex: 1 }}>
                <input className="scrub" type="range" min={0} max={seqs.length} value={cursor} onChange={(e) => { setPlaying(false); setCursor(+e.target.value); }} aria-label="Step" />
                <div className="act-bar"><i ref={barRef as React.RefObject<HTMLElement>} style={{ width: 0 }} /></div>
              </div>
              <span className="mono muted">{cursor}/{seqs.length}</span>
              <select value={speed} onChange={(e) => setSpeed(+e.target.value)} aria-label="Speed"><option value={0.5}>0.5×</option><option value={1}>1×</option><option value={2}>2×</option><option value={4}>4×</option></select>
              <button className="btn ghost" onClick={stopReplay}><X size={14} /> Close</button>
            </div>
          </div>
        )}

        <div className="hud tr cc-tools-top">
          <button className="btn ghost" onClick={() => handle.current?.fit()} aria-label="Fit graph to view"><Maximize2 size={14} /> Fit</button>
          {(activation || replayEp) && <button className="btn ghost" onClick={() => { setActivation(undefined); if (replayEp) stopReplay(); else handle.current?.fit(); }}><RotateCcw size={14} /> Reset</button>}
        </div>

      </div>

        {/* side dock, outside the canvas: a slim rail until a node is clicked or a button is used */}
        <aside className={`cc-dock glass${dockOpen ? "" : " min"}`} aria-label="Inspector and chat">
          {!dockOpen ? (
            <div className="cc-rail">
              <button onClick={() => { setTab("inspect"); setDockOpen(true); }} aria-label="Open inspector" title="Inspect: click a node on the graph"><ScanSearch size={17} /><span>Inspect</span></button>
              <button onClick={() => { setTab("ask"); setDockOpen(true); }} aria-label="Open ask graph" title="Ask the graph a question"><MessageSquare size={17} /><span>Ask</span></button>
            </div>
          ) : (
            <>
              <div className="cc-tabs" role="tablist">
                <button role="tab" aria-selected={tab === "inspect"} className={tab === "inspect" ? "on" : ""} onClick={() => setTab("inspect")}><ScanSearch size={14} /> Inspect</button>
                <button role="tab" aria-selected={tab === "ask"} className={tab === "ask" ? "on" : ""} onClick={() => setTab("ask")}><MessageSquare size={14} /> Ask graph</button>
                <button className="cc-min" onClick={() => setDockOpen(false)} aria-label="Minimise panel"><ChevronRight size={16} /></button>
              </div>
              {tab === "inspect" ? (
                <div className="cc-dock-body">
                  <Inspector node={picked} scene={scene} paths={paths} notes={Object.fromEntries(Object.entries(narr).map(([k, v]) => [k, v.steps]))}
                    techniques={techs.data ?? []} onPick={pickId} onReplay={(id) => void startReplay(id)} />
                </div>
              ) : (
                <div className="cc-dock-body chat-body">
                  {top.length > 0 && (
                    <div style={{ marginBottom: 8 }}>
                      <div className="muted" style={{ fontSize: 12, marginBottom: 4 }}><Brain size={13} style={{ verticalAlign: -2 }} /> {activation?.size} nodes active</div>
                      {top.map((t) => (
                        <button key={t.id} className="cc-act" onClick={() => pickId(t.id)}>
                          <div className="act-bar"><i style={{ width: `${Math.round(t.v * 100)}%` }} /></div>
                          <span className="muted">{t.n ? `${t.n.kind.replace("_", " ")}: ${t.n.label}` : t.id}</span>
                        </button>
                      ))}
                    </div>
                  )}
                  <div className="chat-log" ref={logRef} aria-live="polite">
                    {msgs.map((m, i) => <div key={i} className={`msg ${m.who === "bot" ? "bot" : m.who === "user" ? "user" : "sys"}`}>{m.text}</div>)}
                    {busy && <div className="msg sys">Searching the graph…</div>}
                  </div>
                  {msgs.length < 3 && <div className="suggest">{SUGGEST.map((s) => <button key={s} onClick={() => void ask(s)}>{s}</button>)}</div>}
                  <form onSubmit={(e) => { e.preventDefault(); void ask(q); }}>
                    <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Ask the graph…" aria-label="Question for the graph" />
                    <button className="btn" disabled={busy || !q.trim()} aria-label="Ask"><Send size={15} /></button>
                  </form>
                </div>
              )}
            </>
          )}
        </aside>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h3>Replay a run</h3>
        <div className="suggest">
          {episodes.map((e) => (
            <button key={e.id} onClick={() => void startReplay(e.id)} title={`${e.kind} · ${e.scenario} · guard ${e.guard_mode}`} style={{ borderColor: e.critical_objective_achieved ? COLORS.breach : undefined }}>
              {e.id.slice(0, 11)} · {e.critical_objective_achieved ? "breached" : "held"}
            </button>
          ))}
          {!episodes.length && <span className="muted">No runs recorded yet. Run an attack with <code>-graph</code>.</span>}
        </div>
      </div>
    </div>
  );
}
