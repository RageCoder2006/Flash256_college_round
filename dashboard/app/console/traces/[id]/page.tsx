"use client";
import Link from "next/link";
import { use } from "react";
import { BreachLine } from "@/components/BreachLine";
import { revealHidden, type TraceFull } from "@/lib/api";
import { useFetch } from "@/lib/use";

function Payload({ text }: { text: string }) {
  const rv = revealHidden(text);
  return (
    <>
      {rv.hiddenCount > 0 && (
        <p style={{ margin: "0 0 8px" }}><span className="note">{rv.hiddenCount} invisible characters. Shown highlighted below; a reader of the document sees nothing.</span></p>
      )}
      <div className="code">
        {rv.parts.map((p, i) => (p.hidden ? <mark key={i} className="hidden-text">{p.t}</mark> : <span key={i}>{p.t}</span>))}
      </div>
    </>
  );
}

function show(v: unknown): string {
  if (typeof v === "string") return v;
  return JSON.stringify(v, null, 2);
}

export default function TraceDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data, error } = useFetch<TraceFull>(`/api/traces/${id}`);
  if (error) return <section className="section"><p className="err">{error}</p></section>;
  if (!data) return <section className="section"><p>Loading…</p></section>;
  const t = data.trace;
  return (
    <>
      <section className="verdict" style={{ paddingBottom: 12 }}>
        <p style={{ margin: 0 }}><Link href="/console/traces">← All traces</Link></p>
        <h1 style={{ fontSize: "clamp(24px,3.4vw,34px)" }}>
          {t.kind === "attack"
            ? <>{t.attack?.technique.replaceAll("_", " ")} via {t.attack?.surface}: <b className={t.success ? "bad" : "good"}>{t.success ? "data leaked" : "contained"}</b></>
            : <>Benign task: <b className={t.success ? "good" : "bad"}>{t.success ? "completed" : "failed"}</b></>}
        </h1>
        <div className="meta" style={{ marginTop: 14 }}>
          <span>Trace <b className="mono">{t.trace_id}</b></span>
          <span>Guard <b>{t.guard_mode}</b></span>
          <span>Model <b>{t.model}</b></span>
          <span>Duration <b>{t.duration_ms} ms</b></span>
          <span>Chain <b style={{ color: data.chain_ok ? "var(--held)" : "var(--breach)" }}>{data.chain_ok ? "verified" : "BROKEN"}</b> <span className="mono">{data.head.slice(0, 12)}</span></span>
          {t.kind === "attack" && <span>Progress <b>{t.progress}/5</b> {t.progress_note}</span>}
        </div>
      </section>

      <section className="section"><header><h2>Path</h2></header><div className="card"><BreachLine nodes={data.strip} /></div></section>

      {t.attack && (
        <section className="section"><header><h2>Planted payload</h2><span className="sub">{t.attack.surface}</span></header><div className="card"><Payload text={t.attack.payload} /></div></section>
      )}

      {(t.verdicts?.length || t.findings?.length) ? (
        <section className="section">
          <header><h2>What the oracle and auditor concluded</h2></header>
          <div className="grid3">
            {t.verdicts?.map((v) => (
              <div className="card" key={v.objective_id}>
                <span className={`sev ${v.success ? "critical" : "low"}`}>{v.success ? "achieved" : "not achieved"}</span>
                <p style={{ margin: "8px 0 0" }}><b>{v.objective_id}</b> {v.asi?.map((a) => <span key={a} className="pill" style={{ marginLeft: 4 }}>{a}</span>)}</p>
                {v.evidence && <p style={{ margin: "6px 0 0", color: "var(--ink-2)" }}>{v.evidence}</p>}
              </div>
            ))}
            {t.findings?.map((f, i) => (
              <div className="card" key={i}>
                <span className={`sev ${f.severity}`}>{f.severity}</span> <span className="mono">{f.kind}</span>
                <p style={{ margin: "8px 0 0", color: "var(--ink-2)" }}>{f.detail}</p>
              </div>
            ))}
          </div>
        </section>
      ) : null}

      <section className="section">
        <header><h2>Step by step</h2><span className="sub">{t.steps.length} steps</span></header>
        <div className="card">
          <ol className="steps">
            {t.steps.map((s) => (
              <li className="step" key={s.seq}>
                <span className="n">{s.seq}</span>
                <span className={`t ${s.type}`}>{s.type}</span>
                <div>
                  {s.type === "user_turn" && <div>{String(s.data.text)}</div>}
                  {s.type === "llm_response" && (
                    <div>
                      {String(s.data.text || "") || <span style={{ color: "var(--ink-3)" }}>(tool call only)</span>}
                      {Array.isArray(s.data.tool_calls) && s.data.tool_calls.length > 0 && <div className="mono" style={{ color: "var(--ink-3)" }}>calls {(s.data.tool_calls as { name: string }[]).map((c) => c.name).join(", ")}</div>}
                    </div>
                  )}
                  {s.type === "tool_call" && <pre>{String(s.data.name)}({show(s.data.args)})</pre>}
                  {s.type === "tool_result" && <pre>{show(s.data.content).slice(0, 1200)}</pre>}
                  {s.type === "guard" && (
                    <div>
                      <b style={{ color: s.data.decision === "allow" ? "var(--ink-2)" : "var(--held)" }}>{String(s.data.decision)}</b>{" "}
                      <span className="mono">{Array.isArray(s.data.rule_ids) ? (s.data.rule_ids as string[]).join("+") : ""}</span>
                      <div style={{ color: "var(--ink-2)" }}>{String(s.data.reason ?? "")}</div>
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ol>
        </div>
      </section>
    </>
  );
}
