"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { Download, Eye, FileArchive, FilePlus2, Trash2, X } from "lucide-react";
import { RunSummary } from "@/components/reports/RunSummary";
import { ago } from "@/components/intel/shared";
import { ApiError, del, get, getBlob, post, saveBlob, type Evaluation, type ReportData, type ReportMeta, type ReportRuns, type RunRow } from "@/lib/api";
import { fmtBytes } from "@/lib/status";
import { useFetch } from "@/lib/use";

const FORMAT_LABEL: Record<string, string> = { html: "HTML", pdf: "PDF", md: "Markdown", json: "JSON", sarif: "SARIF" };
const ratingColor = (r: string) => (/critical/i.test(r) ? "#ff5577" : /high/i.test(r) ? "#ff7a45" : /medium/i.test(r) ? "#ffd447" : /no critical/i.test(r) ? "#35e3ac" : "#8a9cc4");

// Go encodes an empty list as null; the page wants arrays.
function normalise(r: ReportData): ReportData {
  const a = <T,>(v: T[] | null | undefined): T[] => v ?? [];
  return {
    ...r, findings: a(r.findings).map((f) => ({ ...f, stopped_by: a(f.stopped_by), owasp_agentic: a(f.owasp_agentic), taxonomy: a(f.taxonomy), intel: a(f.intel) })),
    techniques: a(r.techniques), objectives: a(r.objectives), recommendations: a(r.recommendations), limitations: a(r.limitations),
    scope: { ...r.scope, agent_tools: a(r.scope?.agent_tools), surfaces: a(r.scope?.surfaces), objectives: a(r.scope?.objectives), techniques_tried: a(r.scope?.techniques_tried) },
    threat_context: r.threat_context ? { ...r.threat_context, refs: a(r.threat_context.refs) } : undefined,
  };
}

interface Preview { title: string; kind: "html" | "pdf" | "text"; html?: string; url?: string; text?: string }

export default function ReportsPage() {
  const runs = useFetch<ReportRuns>("/api/reports/runs", 20000);
  const who = useFetch<{ role: string }>("/api/whoami");
  const role = who.data?.role ?? "viewer";
  const canGenerate = role === "operator" || role === "admin";
  const [run, setRun] = useState<string>("");
  const [tab, setTab] = useState<"summary" | "files">("summary");
  const [data, setData] = useState<ReportData | null>(null);
  const [ev, setEv] = useState<Evaluation | null>(null);
  const [files, setFiles] = useState<ReportMeta[]>([]);
  const [msg, setMsg] = useState<{ bad: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ skeleton: "security-report", format: "html", title: "", classification: "CONFIDENTIAL" });
  const [preview, setPreview] = useState<Preview | null>(null);
  const urlRef = useRef<string | null>(null);

  useEffect(() => { if (!run && runs.data?.runs.length) setRun(runs.data.runs[0].id); }, [runs.data, run]);
  useEffect(() => { const d = runs.data?.defaults; if (d) setForm((f) => ({ ...f, skeleton: d.report_skeleton || f.skeleton, title: d.report_title || "", classification: d.classification || f.classification })); }, [runs.data?.defaults]);

  const loadRun = useCallback(async (id: string) => {
    setData(null);
    setEv(null);
    setMsg(null);
    try {
      const [r, f, e] = await Promise.all([get<ReportData>(`/api/reports/runs/${id}/summary`), get<ReportMeta[]>(`/api/reports/files?run=${id}`), get<Evaluation>(`/api/reports/runs/${id}/evaluation`).catch(() => null)]);
      setData(normalise(r));
      setEv(e);
      setFiles(f ?? []);
    } catch (e) {
      setFiles([]);
      setMsg({ bad: true, text: e instanceof Error ? e.message : String(e) });
    }
  }, []);
  useEffect(() => { if (run) void loadRun(run); }, [run, loadRun]);

  const closePreview = () => { if (urlRef.current) URL.revokeObjectURL(urlRef.current); urlRef.current = null; setPreview(null); };

  async function open(m: ReportMeta) {
    try {
      const blob = await getBlob(`/api/reports/files/${m.run}/${m.id}`);
      showBlob(blob, m.format, `${FORMAT_LABEL[m.format]} · ${m.id}`);
    } catch (e) { setMsg({ bad: true, text: e instanceof Error ? e.message : String(e) }); }
  }
  async function showBlob(blob: Blob, format: string, title: string) {
    if (urlRef.current) URL.revokeObjectURL(urlRef.current);
    urlRef.current = null;
    if (format === "html") setPreview({ title, kind: "html", html: await blob.text() });
    else if (format === "pdf") { const u = URL.createObjectURL(blob); urlRef.current = u; setPreview({ title, kind: "pdf", url: u }); }
    else {
      let t = await blob.text();
      if (format === "json" || format === "sarif") { try { t = JSON.stringify(JSON.parse(t), null, 2); } catch { /* show as is */ } }
      setPreview({ title, kind: "text", text: t });
    }
  }
  async function previewNow() {
    setBusy(true);
    try {
      const q = new URLSearchParams({ run, format: form.format, skeleton: form.skeleton, title: form.title, classification: form.classification });
      showBlob(await getBlob(`/api/report?${q}`), form.format, `Preview · ${FORMAT_LABEL[form.format]} (not saved)`);
    } catch (e) { setMsg({ bad: true, text: e instanceof ApiError ? e.message : String(e) }); } finally { setBusy(false); }
  }
  async function generate() {
    setBusy(true);
    setMsg(null);
    try {
      const m = await post<ReportMeta>("/api/reports/generate", { run, ...form });
      setMsg({ bad: false, text: `Saved ${FORMAT_LABEL[m.format]} report ${m.id} (${fmtBytes(m.bytes)}).` });
      setTab("files");
      await loadRun(run);
      runs.reload();
    } catch (e) { setMsg({ bad: true, text: e instanceof Error ? e.message : String(e) }); } finally { setBusy(false); }
  }
  async function download(m: ReportMeta) {
    try { saveBlob(await getBlob(`/api/reports/files/${m.run}/${m.id}?download=1`), `avhsol-${m.run}-${m.id}.${m.format}`); } catch (e) { setMsg({ bad: true, text: e instanceof Error ? e.message : String(e) }); }
  }
  async function zip() {
    try { saveBlob(await getBlob(`/api/reports/runs/${run}/zip`), `avhsol-${run}-reports.zip`); } catch (e) { setMsg({ bad: true, text: e instanceof Error ? e.message : String(e) }); }
  }
  async function remove(m: ReportMeta) {
    try { await del(`/api/reports/files/${m.run}/${m.id}`); await loadRun(run); runs.reload(); } catch (e) { setMsg({ bad: true, text: e instanceof Error ? e.message : String(e) }); }
  }

  const sel: RunRow | undefined = runs.data?.runs.find((r) => r.id === run);
  return (
    <div>
      <div className="page-head"><h1>Reports</h1><p className="muted">Every run, its executive summary and findings, and every report generated for it. Preview in place, then download.</p></div>
      <div className="rp-split">
        <aside className="rp-runs" aria-label="Runs">
          {(runs.data?.runs ?? []).map((r) => (
            <button key={r.id} className={`rp-run${run === r.id ? " on" : ""}`} onClick={() => { setRun(r.id); setTab("summary"); }}>
              <div className="rp-top"><b>{r.id}</b><span className="ti-pill" style={{ ["--c" as string]: ratingColor(r.rating) }}>{r.simulated ? "simulated" : r.rating.replace("No critical exploit observed", "none critical")}</span></div>
              <div className="muted" style={{ fontSize: 12 }}>{r.scenario || "no scenario"} · {r.target || "?"}</div>
              <div className="rp-bar"><i style={{ width: `${Math.round(r.asr * 100)}%`, opacity: r.simulated ? 0.35 : 1 }} /></div>
              <div className="muted" style={{ fontSize: 11.5, display: "flex", justifyContent: "space-between" }}><span>{r.exploits}/{r.valid_runs} critical · {r.traces} traces</span><span>{r.reports ? `${r.reports} report${r.reports > 1 ? "s" : ""}` : "no reports"}</span></div>
              <div className="muted" style={{ fontSize: 11 }}>{ago(r.modified)}</div>
            </button>
          ))}
          {!runs.data?.runs.length && <div className="muted" style={{ padding: 14 }}>No runs found. Start one from Run, then come back.</div>}
        </aside>

        <div>
          {sel && (
            <div className="seg" role="tablist" style={{ marginBottom: 12 }}>
              <button role="tab" aria-pressed={tab === "summary"} onClick={() => setTab("summary")}>Summary</button>
              <button role="tab" aria-pressed={tab === "files"} onClick={() => setTab("files")}>Reports · {files.length}</button>
            </div>
          )}
          {msg && <div className={`ti-msg${msg.bad ? " bad" : ""}`} role="status">{msg.text}</div>}
          {tab === "summary" && (data ? <RunSummary r={data} ev={ev} /> : <div className="muted">{msg ? "" : "Loading the assessment…"}</div>)}
          {tab === "files" && sel && (
            <div>
              <div className="panel" style={{ marginBottom: 12 }}>
                <h3>Generate a report <span>{sel.id}</span></h3>
                <div className="rp-form">
                  <label>Layout<select value={form.skeleton} onChange={(e) => setForm({ ...form, skeleton: e.target.value })}>{(runs.data?.skeletons ?? []).map((s) => <option key={s}>{s}</option>)}</select></label>
                  <label>Format<select value={form.format} onChange={(e) => setForm({ ...form, format: e.target.value })}>{(runs.data?.formats ?? []).map((f) => <option key={f} value={f} disabled={f === "pdf" && !runs.data?.pdf}>{FORMAT_LABEL[f] ?? f}{f === "pdf" && !runs.data?.pdf ? " (needs Chrome)" : ""}</option>)}</select></label>
                  <label>Title<input value={form.title} maxLength={120} onChange={(e) => setForm({ ...form, title: e.target.value })} placeholder="Default title" /></label>
                  <label>Classification<input value={form.classification} maxLength={40} onChange={(e) => setForm({ ...form, classification: e.target.value })} /></label>
                </div>
                <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
                  <button className="btn ghost" disabled={busy} onClick={() => void previewNow()}><Eye size={14} /> Preview without saving</button>
                  <button className="btn" disabled={busy || !canGenerate} onClick={() => void generate()} title={canGenerate ? "" : "Operators and admins can save reports"}><FilePlus2 size={14} /> Generate and save</button>
                  {!canGenerate && <span className="muted" style={{ fontSize: 12.5, alignSelf: "center" }}>Your role can preview and download but not save new reports.</span>}
                </div>
              </div>
              <div className="panel">
                <h3>Saved reports <span>{files.length ? `${files.length} for ${sel.id}` : ""}</span></h3>
                {files.length === 0 ? <p className="muted" style={{ margin: 0 }}>None yet. Generate one above.</p> : (
                  <>
                    <table className="tbl"><thead><tr><th>Format</th><th>Layout</th><th>Size</th><th>Created</th><th>sha256</th><th /></tr></thead>
                      <tbody>{files.map((m) => (
                        <tr key={m.id}>
                          <td><span className="ti-pill" style={{ ["--c" as string]: "#8f80ff" }}>{FORMAT_LABEL[m.format] ?? m.format}</span></td>
                          <td>{m.skeleton}{m.classification ? <span className="muted"> · {m.classification}</span> : null}</td>
                          <td>{fmtBytes(m.bytes)}</td>
                          <td title={m.created_at}>{ago(m.created_at)} <span className="muted">· {m.created_by}</span></td>
                          <td><code>{m.sha256.slice(0, 10)}…</code></td>
                          <td style={{ whiteSpace: "nowrap", textAlign: "right" }}>
                            <button className="btn ghost sm" onClick={() => void open(m)}><Eye size={13} /> Preview</button>{" "}
                            <button className="btn ghost sm" onClick={() => void download(m)}><Download size={13} /> Download</button>
                            {role === "admin" && <>{" "}<button className="btn ghost sm" onClick={() => void remove(m)} aria-label={`Delete ${m.id}`}><Trash2 size={13} /></button></>}
                          </td>
                        </tr>
                      ))}</tbody></table>
                    <button className="btn ghost" style={{ marginTop: 10 }} onClick={() => void zip()}><FileArchive size={14} /> Download all as a zip</button>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {preview && (
        <div className="rp-modal" role="dialog" aria-modal="true" aria-label={preview.title} onKeyDown={(e) => e.key === "Escape" && closePreview()}>
          <div className="rp-sheet">
            <div className="rp-bar2"><b>{preview.title}</b><button className="btn ghost sm" onClick={closePreview} autoFocus><X size={14} /> Close</button></div>
            {preview.kind === "html" && <iframe title={preview.title} sandbox="" srcDoc={preview.html} />}
            {preview.kind === "pdf" && <iframe title={preview.title} src={preview.url} />}
            {preview.kind === "text" && <pre>{preview.text}</pre>}
          </div>
        </div>
      )}
    </div>
  );
}
