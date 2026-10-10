"use client";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { post, streamEvents } from "@/lib/api";

type Kind = "validate" | "hunt" | "campaign";
const DESC: Record<Kind, string> = {
  validate: "Attack with the guard off, replay every working exploit with the guard enforcing, run the benign tasks both ways, then ablate each defense.",
  hunt: "Let the attacker search on its own: it picks techniques, mutates payloads, re-runs winners and shrinks them.",
  campaign: "Run the fixed seed attacks once and report the attack success rate.",
};

function cls(line: string) {
  if (/EXPLOITED|DISCOVERY|data leaked/.test(line)) return "hit";
  if (/resisted|OK|PASS|blocked/.test(line)) return "ok";
  if (line.startsWith("$") || line.startsWith("==")) return "dim";
  return "";
}

export default function Run() {
  const [kind, setKind] = useState<Kind>("validate");
  const [offline, setOffline] = useState(true);
  const [budget, setBudget] = useState(30);
  const [vsDefense, setVsDefense] = useState(true);
  const [lines, setLines] = useState<string[]>([]);
  const [status, setStatus] = useState<"idle" | "running" | "done" | "failed">("idle");
  const [error, setError] = useState<string | null>(null);
  const box = useRef<HTMLDivElement>(null);
  const abort = useRef<AbortController | null>(null);

  useEffect(() => () => abort.current?.abort(), []);
  useEffect(() => {
    box.current?.scrollTo({ top: box.current.scrollHeight });
  }, [lines]);

  async function start() {
    setError(null);
    setLines([]);
    try {
      const run = await post<{ id: string }>("/api/runs", { kind, offline, budget, vs_defense: vsDefense, regress: true });
      setStatus("running");
      const ctl = new AbortController();
      abort.current = ctl;
      streamEvents(`/api/runs/${run.id}/stream`, (ev, data) => {
        if (ev === "line") setLines((l) => [...l, JSON.parse(data)]);
        if (ev === "end") setStatus(JSON.parse(data) === "done" ? "done" : "failed");
      }, ctl.signal).catch(() => setStatus((s) => (s === "running" ? "failed" : s)));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStatus("idle");
    }
  }

  return (
    <section className="section">
      <header><h2>Run</h2><span className="sub">Runs start on this machine and write traces you can open under Traces.</span></header>
      <div className="card">
        <div className="seg" role="group" aria-label="Run type" style={{ marginBottom: 10 }}>
          {(["validate", "hunt", "campaign"] as Kind[]).map((k) => (
            <button key={k} aria-pressed={kind === k} onClick={() => setKind(k)}>{k === "validate" ? "Validate the guard" : k === "hunt" ? "Hunt autonomously" : "Seed campaign"}</button>
          ))}
        </div>
        <p style={{ color: "var(--ink-2)", margin: "0 0 14px", maxWidth: "70ch" }}>{DESC[kind]}</p>
        <div className="form">
          <label className="check"><input type="checkbox" checked={offline} onChange={(e) => setOffline(e.target.checked)} /> Simulated model (no LLM needed)</label>
          {kind === "hunt" && (
            <>
              <label>Attempts<input type="number" min={1} max={500} value={budget} onChange={(e) => setBudget(Number(e.target.value))} /></label>
              <label className="check"><input type="checkbox" checked={vsDefense} onChange={(e) => setVsDefense(e.target.checked)} /> Then hunt the enforcing guard</label>
            </>
          )}
          <button className="btn" onClick={start} disabled={status === "running"}>{status === "running" ? "Running…" : `Start ${kind}`}</button>
        </div>
        {!offline && <p style={{ margin: "12px 0 0", color: "var(--ink-3)", fontSize: 13 }}>Uses the model set in AVHSOL_LLM_BASE_URL and AVHSOL_LLM_MODEL on the server.</p>}
        {error && <p className="err" style={{ marginTop: 12 }}>{error}</p>}
      </div>
      <div style={{ marginTop: 16 }}>
        <div className="console" ref={box} role="log" aria-live="polite" aria-label="Run output">
          {lines.length === 0 && <span className="dim">Output appears here.</span>}
          {lines.map((l, i) => <div key={i} className={cls(l)}>{l}</div>)}
        </div>
        {status === "done" && <p>Finished. <Link href="/">See the verdict</Link> or <Link href="/console/traces">browse traces</Link>.</p>}
        {status === "failed" && <p className="err">The run failed. The last lines above say why.</p>}
      </div>
    </section>
  );
}
