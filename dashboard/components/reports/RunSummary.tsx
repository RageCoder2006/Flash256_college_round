"use client";
import { useState } from "react";
import { ChevronDown, ChevronRight, ShieldCheck } from "lucide-react";
import type { Evaluation, Rate, ReportData } from "@/lib/api";
import { sevColor } from "@/components/intel/shared";

const ratingColor = (r: string) => (/critical/i.test(r) ? "#ff5577" : /high/i.test(r) ? "#ff7a45" : /medium/i.test(r) ? "#ffd447" : /no critical/i.test(r) ? "#35e3ac" : "#8a9cc4");

function Sec({ title, children, hint }: { title: string; children: React.ReactNode; hint?: string }) {
  return <section className="panel" style={{ marginBottom: 12 }}><h3>{title}{hint && <span>{hint}</span>}</h3>{children}</section>;
}

/** The report's content as data, in the dashboard theme: executive summary first, then scope, results, findings, defenses, advice, limits and integrity. */
/** A rate with its 95% interval drawn as a bar with a range. */
function RateBar({ r, color = "#ff5577" }: { r: Rate; color?: string }) {
  if (!r.n) return <span className="muted">n/a</span>;
  return (
    <div style={{ minWidth: 150 }} title={`${r.k} of ${r.n}: ${(r.p * 100).toFixed(0)}%, 95% interval ${(r.low * 100).toFixed(0)} to ${(r.high * 100).toFixed(0)}%`}>
      <div style={{ position: "relative", height: 8, borderRadius: 4, background: "rgba(130,160,230,0.14)" }}>
        <i style={{ position: "absolute", left: `${r.low * 100}%`, width: `${Math.max(1, (r.high - r.low) * 100)}%`, top: 0, bottom: 0, background: color, opacity: 0.28, borderRadius: 4 }} />
        <i style={{ position: "absolute", left: `${r.p * 100}%`, top: -2, width: 3, height: 12, background: color, borderRadius: 2 }} />
      </div>
      <div className="muted" style={{ fontSize: 11, marginTop: 2 }}>{r.k}/{r.n} · {(r.p * 100).toFixed(0)}% <span>({(r.low * 100).toFixed(0)}-{(r.high * 100).toFixed(0)}%)</span></div>
    </div>
  );
}

export function RunSummary({ r, ev }: { r: ReportData; ev?: Evaluation | null }) {
  const [open, setOpen] = useState<string | null>(null);
  const col = ratingColor(r.risk_rating);
  return (
    <div>
      <Sec title="Executive summary" hint={`${r.doc.report_id} · ${r.doc.date}`}>
        {r.simulated && <div className="ti-msg bad" style={{ marginTop: 0 }}>Some runs used the simulated model. They test the tooling, not any real agent, so this assessment is not rated.</div>}
        <div style={{ display: "flex", gap: 16, alignItems: "flex-start", flexWrap: "wrap" }}>
          <div className="mtile" style={{ ["--c" as string]: col, minWidth: 180 }}><div className="mt-l">Overall rating</div><div className="mt-v" style={{ color: col, fontSize: 19 }}>{r.risk_rating}</div></div>
          <div style={{ flex: 1, minWidth: 260 }}>
            <p style={{ margin: "0 0 8px", fontSize: 15.5, lineHeight: 1.55 }}>{r.headline}</p>
            <p className="muted" style={{ margin: 0, fontSize: 13 }}>{r.risk_basis}</p>
          </div>
        </div>
        <div className="st-grid c4" style={{ margin: "12px 0 0" }}>
          <div className="mtile" style={{ ["--c" as string]: "#ff5577" }}><div className="mt-l">Valid attack runs</div><div className="mt-v">{r.valid_runs}</div><div className="mt-s">of {r.attack_runs} attempted</div></div>
          <div className="mtile" style={{ ["--c" as string]: "#8a9cc4" }}><div className="mt-l">Errored (excluded)</div><div className="mt-v">{r.errored_runs}</div></div>
          <div className="mtile" style={{ ["--c" as string]: "#35e3ac" }}><div className="mt-l">No-attack control runs</div><div className="mt-v">{r.control_runs}</div><div className="mt-s">{r.control_runs ? "baseline present" : "none: habits not separated"}</div></div>
          <div className="mtile" style={{ ["--c" as string]: "#ffb454" }}><div className="mt-l">Distinct findings</div><div className="mt-v">{r.findings.length}</div></div>
        </div>
      </Sec>

      {ev && (
        <Sec title="Evaluation" hint="rates with 95% intervals, compared with the no-attack control">
          <div style={{ display: "flex", gap: 22, flexWrap: "wrap", alignItems: "center", marginBottom: 10 }}>
            <div><div className="mt-l">Critical exploit rate</div><RateBar r={ev.exploit} /></div>
            {Object.keys(ev.severity).length > 0 && <div className="chart-legend">{Object.entries(ev.severity).map(([k, n]) => <span key={k}><i style={{ background: sevColor(k) }} />{k} <b>{n}</b></span>)}</div>}
            {ev.max_stages > 1 && <span className="ti-pill" style={{ ["--c" as string]: "#c9a8ff" }}>up to {ev.max_stages} stages · {ev.multi_stage_findings} multi-stage</span>}
          </div>
          <table className="tbl"><thead><tr><th>Objective</th><th>Attack</th><th>Control</th><th>What that means</th></tr></thead>
            <tbody>{ev.objectives.map((o) => (
              <tr key={o.objective}>
                <td style={{ whiteSpace: "nowrap" }}>{o.objective.replace(/_/g, " ")} <span className="ti-pill" style={{ ["--c" as string]: sevColor(o.severity) }}>{o.severity}</span></td>
                <td><RateBar r={o.attack} /></td><td><RateBar r={o.control} color="#35e3ac" /></td>
                <td style={{ fontSize: 12.5, color: "var(--ink-2)", lineHeight: 1.45 }}>{o.verdict}</td>
              </tr>
            ))}</tbody></table>
          {ev.defense && (
            <div style={{ marginTop: 12 }}>
              <div className="cc-title">Defenses</div>
              <p style={{ margin: "0 0 6px", fontSize: 13.5 }}>{ev.defense.verdict}</p>
              {ev.defense.contribution && ev.defense.contribution.length > 0 && <div className="chart-legend">{ev.defense.contribution.map((c) => <span key={c.defense}>without {c.defense} <b style={{ color: c.matters ? "#ff5577" : undefined }}>{c.success_without_it.k}/{c.success_without_it.n}</b>{c.matters ? " (it matters)" : ""}</span>)}</div>}
            </div>
          )}
          <p className="muted" style={{ fontSize: 12, margin: "10px 0 0" }}>{ev.does_not_show.join(" ")}</p>
        </Sec>
      )}

      <div className="st-grid c2">
        <Sec title="Scope and method">
          <p style={{ margin: "0 0 8px", fontSize: 13.5, lineHeight: 1.55 }} className="muted">{r.scope.description}</p>
          <table className="tbl"><tbody>
            <tr><td className="muted" style={{ width: 120 }}>Agent</td><td>{r.target} · {r.scope.target_kind || "n/a"}{r.scope.sandboxed ? " · sandboxed" : ""}</td></tr>
            <tr><td className="muted">Model</td><td>{r.model}</td></tr>
            <tr><td className="muted">Tools</td><td>{r.scope.agent_tools.join(", ") || "n/a"}</td></tr>
            <tr><td className="muted">Attack surfaces</td><td>{r.scope.surfaces.join(", ")}</td></tr>
            <tr><td className="muted">Techniques tried</td><td>{r.scope.techniques_tried.map((t) => t.replace(/_/g, " ")).join(", ")}</td></tr>
          </tbody></table>
          <div className="cc-title" style={{ marginTop: 12 }}>Critical objectives checked</div>
          {r.scope.objectives.map((o) => <div key={o.id} style={{ fontSize: 13, padding: "3px 0" }}><span className="ti-pill" style={{ ["--c" as string]: sevColor(o.severity), marginRight: 8 }}>{o.severity}</span>{o.description}</div>)}
        </Sec>
        <Sec title="Attack versus control" hint="decided by deterministic checks, never the model">
          <table className="tbl"><thead><tr><th>Objective</th><th>Attack</th><th>Control</th></tr></thead>
            <tbody>{r.objectives.map((o) => <tr key={o.objective}><td>{o.objective.replace(/_/g, " ")} <span className="ti-pill" style={{ ["--c" as string]: sevColor(o.severity) }}>{o.severity}</span></td><td><b>{o.attack}</b></td><td className="muted">{o.control}</td></tr>)}</tbody></table>
          <div className="cc-title" style={{ marginTop: 14 }}>By technique</div>
          {r.techniques.map((t) => (
            <div key={t.technique} style={{ margin: "5px 0" }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12.5 }}><span>{t.technique.replace(/_/g, " ")}</span><span className="muted">{t.wins ?? 0} of {t.runs ?? 0}</span></div>
              <div className="act-bar"><i style={{ width: `${Math.round((t.rate ?? 0) * 100)}%`, background: "linear-gradient(90deg,#ffb454,#ff5577)" }} /></div>
            </div>
          ))}
        </Sec>
      </div>

      <Sec title={`Findings · ${r.findings.length}`} hint="click one to expand">
        {r.findings.length === 0 && <p className="muted" style={{ margin: 0 }}>No attack achieved a critical objective. That is not proof the agent is safe: it only covers the techniques tried.</p>}
        {r.findings.map((f) => (
          <div key={f.id} style={{ borderTop: "1px solid var(--line)" }}>
            <button onClick={() => setOpen(open === f.id ? null : f.id)} style={{ all: "unset", cursor: "pointer", display: "flex", gap: 10, alignItems: "center", padding: "9px 2px", width: "100%", boxSizing: "border-box" }} aria-expanded={open === f.id}>
              {open === f.id ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
              <code style={{ color: "var(--cyan)" }}>{f.id}</code>
              <span style={{ flex: 1, fontSize: 13.5 }}>{f.title}</span>
              <span className="ti-pill" style={{ ["--c" as string]: sevColor(f.severity) }}>{f.severity}</span>
              <span className="muted" style={{ fontSize: 12 }}>{f.reliability_text || `${f.successes}/${f.runs}`}</span>
              {f.guarded_replays > 0 && <span className="ti-pill" style={{ ["--c" as string]: f.guarded_replays_still_succeeding ? "#ff5577" : "#35e3ac" }}>{f.guarded_replays_still_succeeding ? "guard bypassed" : "guard held"}</span>}
            </button>
            {open === f.id && (
              <div style={{ padding: "0 0 12px 25px", fontSize: 13, lineHeight: 1.55 }}>
                <p style={{ margin: "0 0 6px" }}><b>Evidence.</b> {f.evidence}</p>
                <p className="muted" style={{ margin: "0 0 6px" }}>Technique {f.technique.replace(/_/g, " ")} via {f.surface}. {f.guarded_replays} guarded replay(s), {f.guarded_replays_still_succeeding} still succeeding.{f.stopped_by?.length ? ` Stopped by ${f.stopped_by.join(", ")}.` : ""}</p>
                {(f.owasp_agentic?.length || f.taxonomy?.length) ? <p className="muted" style={{ margin: "0 0 6px" }}>Framework ids: {[...(f.owasp_agentic ?? []), ...(f.taxonomy ?? [])].filter((v, i, a) => a.indexOf(v) === i).join(", ")}</p> : null}
                {f.intel && f.intel.length > 0 && <div><div className="cc-title">Related public advisories</div>{f.intel.map((i) => <div key={i.id} style={{ padding: "2px 0" }}><code>{i.id}</code> {i.title.slice(0, 100)} <span className="muted">· {i.why}</span></div>)}</div>}
              </div>
            )}
          </div>
        ))}
      </Sec>

      <div className="st-grid c2">
        {r.defense_summary && (
          <Sec title="Defense results">
            <div className="st-grid c4" style={{ margin: 0 }}>
              <div className="mtile" style={{ ["--c" as string]: "#35e3ac" }}><div className="mt-l">Exploits replayed</div><div className="mt-v">{r.defense_summary.replayed}</div></div>
              <div className="mtile" style={{ ["--c" as string]: "#35e3ac" }}><div className="mt-l">Blocked</div><div className="mt-v">{r.defense_summary.blocked}</div></div>
              <div className="mtile" style={{ ["--c" as string]: "#ff5577" }}><div className="mt-l">Still succeeding</div><div className="mt-v">{r.defense_summary.still_succeeding}</div></div>
              <div className="mtile" style={{ ["--c" as string]: "#4dd8ff" }}><div className="mt-l">Normal tasks pass</div><div className="mt-v" style={{ fontSize: 17 }}>{r.defense_summary.benign_guard_on || "n/a"}</div><div className="mt-s">guard off: {r.defense_summary.benign_guard_off || "n/a"}</div></div>
            </div>
          </Sec>
        )}
        <Sec title="Recommendations">
          {r.recommendations.length === 0 && <p className="muted" style={{ margin: 0 }}>None for this run.</p>}
          {r.recommendations.map((x, i) => <div key={i} style={{ padding: "6px 0", borderTop: i ? "1px solid var(--line)" : undefined, fontSize: 13.5 }}><b>{x.priority}. {x.action}</b><div className="muted" style={{ fontSize: 12.5, marginTop: 2 }}>{x.rationale}</div></div>)}
        </Sec>
      </div>

      <div className="st-grid c2">
        <Sec title="Limitations">
          <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 6, fontSize: 13, color: "var(--ink-2)", lineHeight: 1.5 }}>{r.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul>
        </Sec>
        <Sec title="Integrity" hint="evidence you can verify">
          <p style={{ margin: "0 0 6px", fontSize: 13.5 }}><ShieldCheck size={14} style={{ verticalAlign: -2, color: "var(--held)" }} /> {r.integrity.traces} traces: {r.integrity.signed} signed, {r.integrity.verified} verified, {r.integrity.unsigned} unsigned, {r.integrity.failed_verification} failed.</p>
          <p className="muted mono" style={{ margin: 0, fontSize: 11.5, wordBreak: "break-all" }}>report sha256 {r.integrity.report_digest_sha256}</p>
        </Sec>
      </div>

      {r.threat_context && r.threat_context.refs.length > 0 && (
        <Sec title="Threat context" hint="matched by technique, not proof of the same bug">
          <p className="muted" style={{ margin: "0 0 8px", fontSize: 12.5 }}>{r.threat_context.note}</p>
          <table className="tbl"><tbody>{r.threat_context.refs.map((x) => <tr key={x.id}><td><code>{x.id}</code></td><td>{x.severity && <span className="ti-pill" style={{ ["--c" as string]: sevColor(x.severity) }}>{x.severity}</span>}{x.kev && <span className="ti-pill kev" style={{ marginLeft: 4 }}>exploited</span>}</td><td>{x.title.slice(0, 110)}</td></tr>)}</tbody></table>
        </Sec>
      )}
    </div>
  );
}
