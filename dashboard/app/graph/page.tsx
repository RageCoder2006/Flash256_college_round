"use client";
import { useCallback, useEffect, useState } from "react";
import { CausalGraph } from "@/components/CausalGraph";
import { get, post, type Belief, type EpisodeRow, type GraphAnswer, type PathStep, type Subgraph, type TechniqueStat } from "@/lib/api";
import { useFetch } from "@/lib/use";

function when(ms: number) {
  return ms ? new Date(ms).toISOString().replace("T", " ").slice(0, 19) + "Z" : "–";
}

function Techniques() {
  const { data, error } = useFetch<TechniqueStat[]>("/api/graph/techniques", 15000);
  if (error) return <p className="err">{error}</p>;
  if (!data?.length) return <div className="empty">No real-model attack runs in the graph yet. Run with <span className="mono">-graph</span>, or <span className="mono">avhsol graph ingest</span>.</div>;
  return (
    <div className="card">
      <table>
        <thead><tr><th style={{ width: "34%" }}>Technique</th><th className="num" style={{ width: 110 }}>Worked unguarded</th><th style={{ width: 150 }} /><th>Replays stopped by</th></tr></thead>
        <tbody>
          {data.map((t) => (
            <tr key={t.technique}>
              <td>{t.technique.replaceAll("_", " ")}</td>
              <td className="num">{t.succeeded} of {t.episodes}</td>
              <td style={{ width: 120 }}><div className="bar bad" aria-hidden="true"><i style={{ width: `${Math.round(t.rate * 100)}%` }} /></div></td>
              <td>{(t.stopped_by ?? []).map((d) => <span key={d} className="pill held" style={{ marginRight: 4 }}>{d}</span>)}{!t.stopped_by?.length && <span style={{ color: "var(--ink-3)" }}>–</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p style={{ margin: "10px 0 0", color: "var(--ink-3)", fontSize: 13 }}>Real-model runs only; the simulated model is excluded.</p>
    </div>
  );
}

function Ask({ onPick }: { onPick: (id: string) => void }) {
  const [q, setQ] = useState("Which attacks made the agent leak credentials, and which defenses stopped them?");
  const [a, setA] = useState<GraphAnswer | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function go(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      setA(await post<GraphAnswer>("/api/graph/ask", { question: q }));
    } catch (x) {
      setErr(x instanceof Error ? x.message : String(x));
    }
    setBusy(false);
  }
  return (
    <div className="card">
      <form onSubmit={go} className="form">
        <label style={{ flex: 1, minWidth: 280 }}>
          Question
          <textarea value={q} onChange={(e) => setQ(e.target.value)} rows={2} style={{ font: "inherit", padding: "8px 10px", borderRadius: 8, border: "1px solid var(--line)", background: "var(--surface)", color: "var(--ink)", resize: "vertical" }} />
        </label>
        <button className="btn" disabled={busy || !q.trim()}>{busy ? "Thinking…" : "Ask the graph"}</button>
      </form>
      {err && <p className="err" style={{ marginTop: 12 }}>{err}</p>}
      {a && (
        <div style={{ marginTop: 14 }}>
          <div style={{ whiteSpace: "pre-wrap" }}>{a.answer}</div>
          <p style={{ margin: "10px 0 0", fontSize: 13, color: "var(--ink-3)" }}>
            Built from: {a.episodes.map((id) => <button key={id} className="pill" style={{ border: 0, cursor: "pointer", marginRight: 4 }} onClick={() => onPick(id)}>{id}</button>)}
            . Checked against recorded evidence, but written by a model: confirm in the path below.
          </p>
        </div>
      )}
    </div>
  );
}

function Detail({ id, role }: { id: string; role: string }) {
  const [path, setPath] = useState<PathStep[]>([]);
  const [g, setG] = useState<Subgraph | null>(null);
  const [hist, setHist] = useState<Belief[]>([]);
  const [asOf, setAsOf] = useState("");
  const [now, setNow] = useState<Belief[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [obj, setObj] = useState("");
  const [ok, setOk] = useState(false);
  const [ev, setEv] = useState("");
  const [why, setWhy] = useState("");

  const load = useCallback(async () => {
    setErr(null);
    try {
      const [p, sg, h] = await Promise.all([
        get<PathStep[]>(`/api/graph/episodes/${id}/path`),
        get<Subgraph>(`/api/graph/episodes/${id}/subgraph`),
        get<Belief[]>(`/api/graph/episodes/${id}/beliefs?history=1`),
      ]);
      setPath(p);
      setG(sg);
      setHist(h);
      setObj((o) => o || h[0]?.objective || "");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, [id]);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    if (!asOf) { setNow([]); return; }
    get<Belief[]>(`/api/graph/episodes/${id}/beliefs?as_of=${asOf}`).then(setNow).catch(() => setNow([]));
  }, [asOf, id]);

  const times = Array.from(new Set(hist.map((b) => b.rec_from))).sort();
  const canCorrect = role === "analyst" || role === "operator" || role === "admin";
  async function correct(e: React.FormEvent) {
    e.preventDefault();
    setNote(null);
    try {
      const r = await post<{ changed: boolean }>("/api/graph/correct", { episode: id, objective: obj, success: ok, evidence: ev, reason: why });
      setNote(r.changed ? "Recorded. The earlier belief is kept in the history." : "No change: that is already the current belief.");
      await load();
    } catch (x) {
      setNote(x instanceof Error ? x.message : String(x));
    }
  }

  if (err) return <p className="err">{err}</p>;
  return (
    <>
      <div className="card">
        <h3 style={{ fontSize: 16, marginBottom: 8 }}>Causal graph <span className="mono" style={{ color: "var(--ink-3)", fontWeight: 400 }}>{id}</span></h3>
        {g ? <CausalGraph g={g} /> : <p>Loading…</p>}
        <p style={{ margin: "8px 0 0", fontSize: 13, color: "var(--ink-3)" }}>Red dashed arcs: a later call that happened after reading untrusted content. Teal: the guard stepped in. Amber: a secret (shown only as a fingerprint).</p>
      </div>
      <div className="card" style={{ marginTop: 16 }}>
        <h3 style={{ fontSize: 16, marginBottom: 8 }}>Path</h3>
        <ol className="steps">
          {path.filter((p) => p.type !== "llm_response" && !(p.type === "guard" && p.decision === "allow")).map((p) => (
            <li className="step" key={p.seq}>
              <span className="n">{p.seq}</span>
              <span className={`t ${p.type}`}>{p.type}</span>
              <div>
                {p.type === "tool_call" && <pre>{p.name} {p.args}{p.tainted_by !== undefined ? `\n← after untrusted read #${p.tainted_by}` : ""}</pre>}
                {p.type === "tool_result" && <div>{p.source ? <span className="pill breach">untrusted: {p.source}</span> : null} <span style={{ color: "var(--ink-2)" }}>{p.content}</span>{p.secrets?.length ? <span className="pill" style={{ marginLeft: 6 }}>shows secret {p.secrets.join(", ")}</span> : null}</div>}
                {p.type === "guard" && <div><b style={{ color: "var(--held)" }}>{p.decision?.toUpperCase()}</b> <span className="mono">{p.rules?.join("+")}</span> <span style={{ color: "var(--ink-2)" }}>{p.content}</span></div>}
                {p.type === "user_turn" && <div>{p.content}</div>}
                {p.type === "sandbox_event" && <div className="mono" style={{ color: "var(--ink-2)" }}>{p.content}</div>}
              </div>
            </li>
          ))}
        </ol>
      </div>
      <div className="card" style={{ marginTop: 16 }}>
        <h3 style={{ fontSize: 16, marginBottom: 4 }}>What we believed, and when</h3>
        <p style={{ margin: "0 0 10px", color: "var(--ink-3)", fontSize: 13 }}>Two clocks: when it happened, and when we recorded or changed our mind. Corrections never overwrite.</p>
        <table>
          <thead><tr><th>Objective</th><th>Achieved</th><th>Believed from</th><th>Until</th><th>Why</th></tr></thead>
          <tbody>
            {hist.map((b, i) => (
              <tr key={i}>
                <td>{b.objective}</td>
                <td><span className={`pill ${b.success ? "breach" : "held"}`}>{b.success ? "yes" : "no"}</span></td>
                <td className="mono">{when(b.rec_from)}</td>
                <td className="mono">{b.rec_to ? when(b.rec_to) : "now"}</td>
                <td style={{ maxWidth: 360 }}>{b.evidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {times.length > 1 && (
          <div className="form" style={{ marginTop: 12 }}>
            <label>
              What did we believe at
              <select value={asOf} onChange={(e) => setAsOf(e.target.value)} style={{ font: "inherit", padding: "7px 9px", borderRadius: 8, border: "1px solid var(--line)", background: "var(--surface)", color: "var(--ink)" }}>
                <option value="">(choose a moment)</option>
                {times.map((t) => <option key={t} value={t}>{when(t)}</option>)}
              </select>
            </label>
            {asOf && <div>{now.map((b, i) => <div key={i}><b>{b.objective}</b>: {b.success ? "achieved" : "not achieved"}</div>)}</div>}
          </div>
        )}
      </div>
      {canCorrect && hist.length > 0 && (
        <form onSubmit={correct} className="card form" style={{ marginTop: 16 }}>
          <div style={{ flexBasis: "100%" }}><b>Correct a verdict</b> <span style={{ color: "var(--ink-3)", fontSize: 13 }}>(recorded under your role in the audit log)</span></div>
          <label>Objective
            <select value={obj} onChange={(e) => setObj(e.target.value)} style={{ font: "inherit", padding: "7px 9px", borderRadius: 8, border: "1px solid var(--line)", background: "var(--surface)", color: "var(--ink)" }}>
              {Array.from(new Set(hist.map((h) => h.objective))).map((o) => <option key={o}>{o}</option>)}
            </select>
          </label>
          <label className="check"><input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} /> Objective was achieved</label>
          <label style={{ flex: 1, minWidth: 220 }}>Evidence<input value={ev} onChange={(e) => setEv(e.target.value)} style={{ font: "inherit", padding: "7px 9px", borderRadius: 8, border: "1px solid var(--line)", background: "var(--surface)", color: "var(--ink)" }} /></label>
          <label style={{ flex: 1, minWidth: 220 }}>Reason (required)<input value={why} onChange={(e) => setWhy(e.target.value)} style={{ font: "inherit", padding: "7px 9px", borderRadius: 8, border: "1px solid var(--line)", background: "var(--surface)", color: "var(--ink)" }} /></label>
          <button className="btn" disabled={!why.trim() || !ev.trim()}>Record correction</button>
          {note && <p style={{ flexBasis: "100%", margin: 0 }}>{note}</p>}
        </form>
      )}
    </>
  );
}

export default function GraphPage() {
  const status = useFetch<{ configured: boolean }>("/api/graph/status");
  const who = useFetch<{ role: string }>("/api/whoami");
  const eps = useFetch<EpisodeRow[]>("/api/graph/episodes?n=60", 15000);
  const [sel, setSel] = useState("");
  const [kind, setKind] = useState("attack");
  if (status.data && !status.data.configured) {
    return (
      <section className="verdict">
        <h1>The trace graph isn’t connected.</h1>
        <p>Start the stack with <span className="mono">scripts/stack.sh up</span>, then run the API with <span className="mono">-graph</span>. Every run records each step, tool call and guard decision into Neo4j, with vectors in Qdrant.</p>
      </section>
    );
  }
  const rows = (eps.data ?? []).filter((e) => !kind || e.kind === kind);
  return (
    <>
      <section className="verdict" style={{ paddingBottom: 8 }}>
        <h1 style={{ fontSize: "clamp(26px,4vw,40px)" }}>Everything the agent did, as a graph you can ask.</h1>
        <p>Each step is linked to what caused it: which untrusted read tainted a call, which defense judged it, which secret it touched. Verdicts keep their history, so you can see what we believed and when.</p>
      </section>
      <section className="section"><header><h2>What worked, and what stopped it</h2></header><Techniques /></section>
      <section className="section"><header><h2>Ask the graph</h2><span className="sub">retrieves similar steps, expands them through the graph, then answers</span></header><Ask onPick={setSel} /></section>
      <section className="section">
        <header><h2>Episodes</h2></header>
        <div className="filters">
          <div className="seg" role="group" aria-label="Kind">
            {[["attack", "Attacks"], ["benign", "Benign tasks"], ["", "All"]].map(([v, l]) => <button key={v} aria-pressed={kind === v} onClick={() => setKind(v)}>{l}</button>)}
          </div>
        </div>
        {rows.length === 0 ? <div className="empty">Nothing recorded yet.</div> : (
          <div className="card" style={{ overflowX: "auto", maxHeight: 320, overflowY: "auto" }}>
            <table>
              <thead><tr><th>Episode</th><th>Scenario</th><th>Target</th><th>Guard</th><th>Outcome</th><th>When</th></tr></thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id} onClick={() => setSel(e.id)} style={{ cursor: "pointer", background: sel === e.id ? "var(--surface-2)" : undefined }}>
                    <td><button className="mono" style={{ all: "unset", cursor: "pointer", textDecoration: "underline" }} onClick={() => setSel(e.id)}>{e.id}</button></td>
                    <td>{e.scenario}</td><td>{e.target === "unknown-target" ? <span style={{ color: "var(--ink-3)" }}>not recorded</span> : e.target}</td><td className="mono">{e.guard_mode}</td>
                    <td>{e.kind === "attack" ? <span className={`pill ${e.critical_objective_achieved ? "breach" : "held"}`}>{e.critical_objective_achieved ? "achieved" : "held"}</span> : "–"}</td>
                    <td className="mono">{when(e.start_ms)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {sel && <section className="section"><header><h2>Episode</h2></header><Detail id={sel} role={who.data?.role ?? "viewer"} /></section>}
    </>
  );
}
