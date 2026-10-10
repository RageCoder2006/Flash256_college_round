"use client";
import Link from "next/link";
import { useState } from "react";
import { BreachLine } from "@/components/BreachLine";
import { downloadReport, revealHidden, type Advisory, type AuditData, type Pair, type Summary, type Validation } from "@/lib/api";
import { useFetch } from "@/lib/use";

const DEFENSE_NAMES: Record<string, string> = {
  D1: "Fence untrusted content",
  D2: "Strip hidden text",
  D3: "Capability limits",
  D4: "Block egress after untrusted content",
  D5: "Block secrets leaving",
  D6: "Keep tainted contexts off protected files",
  D7: "Approval for destructive tools",
};

function pct(n: number) {
  return `${Math.round(n * 100)}%`;
}

function Verdict({ v }: { v: Validation | null }) {
  if (!v) {
    return (
      <section className="verdict">
        <h1>No validation yet.</h1>
        <p>Run a validation to find what breaks the agent, replay it with the guard enforcing, and check that normal work still goes through.</p>
        <p><Link className="btn" href="/run">Start a validation</Link></p>
      </section>
    );
  }
  const stopped = v.blocked === v.replayed_exploits;
  const intact = v.regression_guard_on.passed === v.regression_guard_on.tasks;
  return (
    <section className="verdict">
      <h1>
        With the guard enforcing, <b className={stopped ? "good" : "bad"}>{v.blocked} of {v.replayed_exploits}</b> working exploits are stopped
        {" "}and <b className={intact ? "good" : "bad"}>{v.regression_guard_on.passed} of {v.regression_guard_on.tasks}</b> legitimate tasks still pass.
      </h1>
      <p>
        Without the guard, {v.baseline.successes} of {v.baseline.attempts} attacks leaked data. The same exploits were replayed unchanged against the enforcing guard.
      </p>
      {v.baseline.offline_simulated && (
        <p><span className="note">Simulated model: this run checks the pipeline and the guard, not how any real model resists attacks.</span></p>
      )}
    </section>
  );
}

function Exploits({ pairs }: { pairs: Pair[] }) {
  const [all, setAll] = useState(false);
  const shown = all ? pairs : pairs.slice(0, 6);
  if (!pairs.length) return <div className="empty">No successful exploits recorded yet.</div>;
  return (
    <div className="card">
      {shown.map((p) => (
        <div className="exploit" key={p.key}>
          <h3>{p.technique.replaceAll("_", " ")} <span>via {p.surface}{p.operator && p.operator !== "none" ? ` · ${p.operator}` : ""}</span></h3>
          {p.off && (
            <div className="lane"><div className="tag">Guard off</div><BreachLine nodes={p.off.strip} /></div>
          )}
          {p.enforce ? (
            <div className="lane"><div className="tag">Guard on</div><BreachLine nodes={p.enforce.strip} /></div>
          ) : (
            <div className="lane"><div className="tag">Guard on</div><span style={{ color: "var(--ink-3)" }}>Not replayed yet.</span></div>
          )}
        </div>
      ))}
      {pairs.length > 6 && (
        <p style={{ margin: "12px 0 0" }}>
          <button className="btn ghost" onClick={() => setAll(!all)}>{all ? "Show fewer" : `Show all ${pairs.length}`}</button>
        </p>
      )}
    </div>
  );
}

function Ablation({ v }: { v: Validation }) {
  const rows = Object.keys(DEFENSE_NAMES).map((d) => ({
    d,
    without: v.ablation?.find((a) => a.defense === d && a.variant === "without"),
    only: v.ablation?.find((a) => a.defense === d && a.variant === "only"),
  }));
  if (!v.ablation?.length) return <div className="empty">No ablation data. Run a validation with ablation on.</div>;
  const cell = (a?: { successes: number; attempts: number }) =>
    a ? <span className={`cell ${a.successes ? "hot" : "cool"}`}>{a.successes}/{a.attempts}</span> : "–";
  return (
    <div className="card">
      <table>
        <thead><tr><th>Defense</th><th className="num">Still work without it</th><th className="num">Still work with only it</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.d}><td><span className="mono">{r.d}</span> {DEFENSE_NAMES[r.d]}</td><td className="num">{cell(r.without)}</td><td className="num">{cell(r.only)}</td></tr>
          ))}
        </tbody>
      </table>
      <p style={{ color: "var(--ink-3)", fontSize: 13, margin: "10px 0 0" }}>
        Exploits that still succeed, out of those replayed. D1 fences model traffic, so it only shows an effect against a live model.
      </p>
    </div>
  );
}

function Utility({ v }: { v: Validation }) {
  const rows = [
    { label: "Guard off", r: v.regression_guard_off },
    { label: "Guard on", r: v.regression_guard_on },
  ];
  return (
    <div className="card">
      <h3 style={{ fontSize: 16, marginBottom: 10 }}>Legitimate tasks</h3>
      {rows.map(({ label, r }) => (
        <div key={label} style={{ marginBottom: 12 }}>
          <div className="kv" style={{ borderBottom: 0, padding: "0 0 4px" }}><span>{label}</span><span>{r.passed} of {r.tasks} pass</span></div>
          <div className="bar" aria-hidden="true"><i style={{ width: pct(r.utility) }} /></div>
        </div>
      ))}
      {v.regression_guard_on.failed?.length ? (
        <p className="err">Broken by the guard: {v.regression_guard_on.failed.join(", ")}</p>
      ) : (
        <p style={{ color: "var(--ink-2)", margin: 0 }}>The guard did not break any benign task.</p>
      )}
    </div>
  );
}

function GuardCost({ v }: { v: Validation }) {
  const m = v.guard_metrics;
  if (!m) return null;
  return (
    <div className="card">
      <h3 style={{ fontSize: 16, marginBottom: 10 }}>What the guard did</h3>
      <div className="kv"><span>Allowed</span><span>{m.decisions.allow ?? 0}</span></div>
      <div className="kv"><span>Denied</span><span>{m.decisions.deny ?? 0}</span></div>
      {Object.entries(m.by_rule).map(([k, n]) => (
        <div className="kv" key={k}><span><span className="mono">{k}</span> {DEFENSE_NAMES[k] ?? ""}</span><span>{n}</span></div>
      ))}
      <div className="kv"><span>Decision time</span><span>p50 {m.decision_latency_us.p50} µs · p99 {m.decision_latency_us.p99} µs</span></div>
    </div>
  );
}

function Audit({ a }: { a: AuditData }) {
  return (
    <div className="card">
      <h3 style={{ fontSize: 16, marginBottom: 4 }}>Permission audit</h3>
      <p style={{ color: "var(--ink-3)", margin: "0 0 8px", fontSize: 13 }}>{a.scenario.name}: {a.scenario.tools.join(", ")}</p>
      {a.findings.length === 0 && <p style={{ margin: 0 }}>No over-privilege found.</p>}
      {a.findings.map((f, i) => (
        <div className="kv" key={i} style={{ alignItems: "flex-start" }}>
          <span><span className={`sev ${f.severity}`}>{f.severity}</span> <span className="mono">{f.kind}</span><br /><span style={{ fontSize: 13 }}>{f.detail}</span></span>
        </div>
      ))}
    </div>
  );
}

function Hunt({ s }: { s: Summary }) {
  const rows = [
    { label: "Guard off", r: s.hunt?.guard_off },
    { label: "Guard enforcing", r: s.hunt?.guard_enforce },
  ].filter((x) => x.r);
  if (!rows.length) return null;
  return (
    <section className="section">
      <header><h2>What the attacker found on its own</h2><span className="sub">adaptive search, not a fixed list</span></header>
      <div className="card">
        {rows.map(({ label, r }) => (
          <div key={label} style={{ marginBottom: 14 }}>
            <p style={{ margin: "0 0 6px", fontWeight: 600 }}>{label}: {r!.discoveries?.length ?? 0} discoveries in {r!.attempts} attempts</p>
            {(r!.discoveries ?? []).map((d) => {
              const rv = revealHidden(d.minimized_payload);
              return (
                <div key={d.trace_id} className="exploit">
                  <h3>{d.arm.replaceAll("|", " · ")} <span>reliability {pct(d.reliability)} over {d.runs} runs · found at attempt {d.found_at_attempt}</span></h3>
                  <div className="code" style={{ marginTop: 6 }}>
                    {rv.parts.map((p, i) => (p.hidden ? <mark key={i} className="hidden-text" title="invisible in the document">{p.t}</mark> : <span key={i}>{p.t}</span>))}
                  </div>
                  <Link href={`/traces/${d.trace_id}`} className="mono">open trace {d.trace_id}</Link>
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </section>
  );
}

function Advisories({ items }: { items: Advisory[] }) {
  const ok = items.filter((a) => !a.error && a.title);
  if (!ok.length) return null;
  return (
    <section className="section">
      <header><h2>Analyst notes</h2><span className="sub">written by {ok[0].model}; explanation only, verdicts come from the oracle</span></header>
      <div className="grid3">
        {ok.map((a) => (
          <div className="card" key={a.trace_id}>
            <h3 style={{ fontSize: 16, marginBottom: 6 }}>{a.title}</h3>
            <p style={{ margin: "0 0 8px" }}>{a.summary}</p>
            <p style={{ margin: "0 0 8px", color: "var(--ink-2)" }}><b>Why it worked.</b> {a.root_cause}</p>
            <ul style={{ margin: 0, paddingLeft: 18 }}>{(a.fixes ?? []).map((f, i) => <li key={i}>{f}</li>)}</ul>
            <p style={{ margin: "10px 0 0" }}><Link className="mono" href={`/traces/${a.trace_id}`}>{a.trace_id}</Link></p>
          </div>
        ))}
      </div>
    </section>
  );
}

function ReportPanel() {
  const info = useFetch<{ skeletons: string[]; formats: string[]; pdf: boolean }>("/api/report/skeletons");
  const [skeleton, setSkeleton] = useState("security-report");
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState<string | null>(null);
  async function get(format: string) {
    setBusy(format);
    setErr(null);
    try {
      await downloadReport(format, skeleton);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
    setBusy("");
  }
  if (!info.data) return null;
  const label: Record<string, string> = { html: "HTML", pdf: "PDF", md: "Markdown", json: "JSON", sarif: "SARIF" };
  return (
    <section className="section">
      <header><h2>Security report</h2><span className="sub">cover, findings with timelines, charts, remediation, limitations</span></header>
      <div className="card form">
        <label>Layout
          <select value={skeleton} onChange={(e) => setSkeleton(e.target.value)} style={{ font: "inherit", padding: "7px 9px", borderRadius: 8, border: "1px solid var(--line)", background: "var(--surface)", color: "var(--ink)" }}>
            {info.data.skeletons.map((s) => <option key={s} value={s}>{s.replaceAll("-", " ")}</option>)}
          </select>
        </label>
        {info.data.formats.filter((f) => f !== "pdf" || info.data!.pdf).map((f) => (
          <button key={f} className="btn ghost" disabled={!!busy} onClick={() => get(f)}>{busy === f ? "Preparing…" : `Download ${label[f] ?? f}`}</button>
        ))}
        {err && <p className="err" style={{ flexBasis: "100%", margin: 0 }}>{err}</p>}
      </div>
    </section>
  );
}

export default function Overview() {
  const sum = useFetch<Summary>("/api/summary", 5000);
  const pairs = useFetch<Pair[]>("/api/pairs", 5000);
  const audit = useFetch<AuditData>("/api/audit");
  const adv = useFetch<Advisory[]>("/api/advisories", 10000);
  if (sum.error && !sum.data) {
    return (
      <section className="verdict">
        <h1>The API isn’t reachable.</h1>
        <p className="err">{sum.error}. Start it with <span className="mono">avhsol serve -addr 127.0.0.1:8787</span>.</p>
      </section>
    );
  }
  const v = sum.data?.validation ?? null;
  return (
    <>
      <Verdict v={v} />
      <section className="section">
        <header><h2>How each exploit travels</h2><span className="sub">red = data left, teal = the guard cut the chain</span></header>
        <Exploits pairs={pairs.data ?? []} />
      </section>
      {v && (
        <section className="section">
          <header><h2>What carried the weight</h2></header>
          <div className="grid3">
            <Ablation v={v} />
            <Utility v={v} />
            <GuardCost v={v} />
          </div>
        </section>
      )}
      {v && <ReportPanel />}
      {sum.data && <Hunt s={sum.data} />}
      {adv.data && <Advisories items={adv.data} />}
      {audit.data && (
        <section className="section">
          <header><h2>Before any attack</h2><span className="sub">static review of what the agent is allowed to do</span></header>
          <Audit a={audit.data} />
        </section>
      )}
    </>
  );
}
