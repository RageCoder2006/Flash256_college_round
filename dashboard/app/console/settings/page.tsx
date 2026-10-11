"use client";
import { useEffect, useState } from "react";
import { CheckCircle2, KeyRound, Lock, RefreshCw, ShieldAlert, Trash2 } from "lucide-react";
import { API, ApiError, get, post, put, setToken, type Catalog, type IntelSources, type Settings } from "@/lib/api";
import { ago } from "@/components/intel/shared";
import type { StatusSnapshot } from "@/lib/status";
import { useFetch } from "@/lib/use";

interface SettingsResp { settings: Settings; catalog: Catalog; defenses: string[]; secrets_note: string }

const DEFENSE: Record<string, [string, string]> = {
  D1: ["Fence untrusted content", "Wraps what the agent reads from outside so the model can tell data from instructions."],
  D2: ["Strip hidden text, scan arguments", "Removes invisible characters and flags injection markers in outgoing arguments."],
  D3: ["Capability limits", "Checks each tool call against what the agent is declared to be allowed to do."],
  D4: ["Block tainted egress", "Stops data leaving after untrusted content, unless the user asked for it."],
  D5: ["Secret in egress", "Blocks outbound calls that carry credentials."],
  D6: ["Protected paths", "Keeps tainted contexts away from files such as .env and key material."],
  D7: ["Approval for destructive actions", "Requires a human for actions that delete or overwrite."],
};

function Section({ title, hint, children, danger }: { title: string; hint?: string; children: React.ReactNode; danger?: boolean }) {
  return <section className="panel" style={{ marginBottom: 14, borderColor: danger ? "rgba(255,85,119,0.4)" : undefined }}><h3 style={danger ? { color: "var(--breach)" } : undefined}>{title}{hint && <span>{hint}</span>}</h3>{children}</section>;
}

export default function SettingsPage() {
  const who = useFetch<{ role: string }>("/api/whoami");
  const role = who.data?.role ?? "viewer";
  const isAdmin = role === "admin";
  const canOperate = role === "operator" || isAdmin;
  const cfg = useFetch<SettingsResp>(canOperate ? "/api/settings" : null);
  const status = useFetch<StatusSnapshot>("/api/status", 15000);
  const intel = useFetch<IntelSources>("/api/intel/sources");
  const guard = useFetch<{ reachable: boolean; mode?: string }>("/api/guard", 5000);
  const pol = useFetch<{ all: string[]; enabled: string[] }>("/api/guard/policy");
  const [draft, setDraft] = useState<Settings | null>(null);
  const [enabled, setEnabled] = useState<string[]>([]);
  const [msg, setMsg] = useState<{ bad: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState("");
  const [llm, setLlm] = useState<{ state: string; detail?: string; latency_ms?: number } | null>(null);
  const [confirm, setConfirm] = useState("");
  const [reduce, setReduce] = useState(false);

  useEffect(() => { if (cfg.data) setDraft(cfg.data.settings); }, [cfg.data]);
  useEffect(() => { if (pol.data) setEnabled(pol.data.enabled); }, [pol.data]);
  useEffect(() => { try { setReduce(localStorage.getItem("avhsol.motion") === "reduce"); } catch { /* storage unavailable */ } }, []);

  const flash = (bad: boolean, text: string) => setMsg({ bad, text });
  const run = async (key: string, fn: () => Promise<string | void>) => {
    setBusy(key);
    setMsg(null);
    try { const t = await fn(); if (t) flash(false, t); } catch (e) { flash(true, e instanceof ApiError || e instanceof Error ? e.message : String(e)); } finally { setBusy(""); }
  };
  const set = <K extends keyof Settings>(k: K, v: Settings[K]) => draft && setDraft({ ...draft, [k]: v });
  const llmHealth = status.data?.health.find((h) => h.id === "llm");
  const cat = cfg.data?.catalog;
  const sources = intel.data?.sources ?? [];

  return (
    <div>
      <div className="page-head"><h1>Settings</h1><p className="muted">Defaults and controls for this AVHSOL installation. Secrets are never kept here: the model key, API tokens and database passwords come from the environment of the processes that need them.</p></div>
      {msg && <div className={`ti-msg${msg.bad ? " bad" : ""}`} role="status">{msg.text}</div>}

      <div className="st-grid c2">
        <Section title="Connection" hint={API.replace(/^https?:\/\//, "")}>
          <table className="tbl"><tbody>
            <tr><td className="muted" style={{ width: 130 }}>Signed in as</td><td><span className="ti-pill" style={{ ["--c" as string]: "#8f80ff" }}>{role}</span></td></tr>
            <tr><td className="muted">What this role can do</td><td style={{ fontSize: 13 }}>{isAdmin ? "Everything: change settings, sync intel, delete reports, reset the graph." : role === "operator" ? "Start and cancel runs, change the guard, save reports." : role === "analyst" ? "Ask questions of the graph and correct verdicts." : "Read everything and download reports."}</td></tr>
          </tbody></table>
          <button className="btn ghost" style={{ marginTop: 10 }} onClick={() => { setToken(""); location.reload(); }}>Sign out</button>
        </Section>

        <Section title="Model" hint="from the API's environment">
          <div className={`hitem ${llmHealth?.state ?? "off"}`} style={{ marginBottom: 10 }}><i className="dot" /><div><b>Model endpoint{llmHealth?.latency_ms ? <span style={{ marginLeft: 6 }}>{llmHealth.latency_ms.toFixed(0)} ms</span> : null}</b><span>{llmHealth?.detail ?? "checking…"}</span></div></div>
          <p className="muted" style={{ fontSize: 12.5, margin: "0 0 8px" }}><KeyRound size={12} style={{ verticalAlign: -1 }} /> The key is shown only as set or not set. To change the endpoint, restart the API with <code>AVHSOL_LLM_BASE_URL</code>, <code>AVHSOL_LLM_MODEL</code> and <code>AVHSOL_LLM_API_KEY</code>.</p>
          <button className="btn ghost" disabled={!canOperate || busy === "llm"} onClick={() => void run("llm", async () => { const r = await post<{ state: string; detail?: string; latency_ms?: number }>("/api/llm/test", {}); setLlm(r); })}>Test connection</button>
          {llm && <span style={{ marginLeft: 10, fontSize: 13 }}>{llm.state === "ok" ? <CheckCircle2 size={14} style={{ verticalAlign: -2, color: "var(--held)" }} /> : null} {llm.detail} {llm.latency_ms ? `· ${llm.latency_ms.toFixed(0)} ms` : ""}</span>}
          {!canOperate && <p className="muted" style={{ fontSize: 12, margin: "8px 0 0" }}>Operators and admins can test the connection.</p>}
        </Section>
      </div>

      <Section title="Test defaults" hint="used when a run is started without choosing otherwise">
        {!canOperate && <p className="muted" style={{ margin: 0 }}>Your role cannot view these settings.</p>}
        {draft && cat && (
          <>
            <div className="rp-form">
              <label>Scenario<select value={draft.scenario} disabled={!isAdmin} onChange={(e) => set("scenario", e.target.value)}>{cat.scenarios.map((s) => <option key={s.path} value={s.path}>{s.name}</option>)}</select></label>
              <label>Seeds<select value={draft.seeds} disabled={!isAdmin} onChange={(e) => set("seeds", e.target.value)}>{cat.seeds.map((s) => <option key={s.path} value={s.path}>{s.name}</option>)}</select></label>
              <label>Agent under test<select value={draft.target} disabled={!isAdmin} onChange={(e) => set("target", e.target.value)}><option value="">Simulated-tool harness</option>{cat.targets.map((s) => <option key={s.path} value={s.path}>{s.name} ({s.kind})</option>)}</select></label>
              <label>Sandbox<select value={draft.isolation} disabled={!isAdmin} onChange={(e) => set("isolation", e.target.value)}><option value="landlock">Landlock (host kernel)</option><option value="gvisor">gVisor (no network)</option></select></label>
              <label>Guard when a run starts<select value={draft.guard_mode} disabled={!isAdmin} onChange={(e) => set("guard_mode", e.target.value)}><option>off</option><option>monitor</option><option>enforce</option></select></label>
              <label>Repeats per attack<input type="number" min={1} max={20} value={draft.repeats} disabled={!isAdmin} onChange={(e) => set("repeats", +e.target.value)} /></label>
              <label>Hunt budget<input type="number" min={1} max={500} value={draft.budget} disabled={!isAdmin} onChange={(e) => set("budget", +e.target.value)} /></label>
              <label>Status refresh (s)<input type="number" min={1} max={60} value={draft.refresh_sec} disabled={!isAdmin} onChange={(e) => set("refresh_sec", +e.target.value)} /></label>
            </div>
            <label className="ti-check" style={{ marginTop: 12 }}><input type="checkbox" checked={draft.offline} disabled={!isAdmin} onChange={(e) => set("offline", e.target.checked)} /> Use the simulated model by default (tests the pipeline only; results are labelled and never rated)</label>
            <div className="cc-title" style={{ marginTop: 14 }}>Report defaults</div>
            <div className="rp-form">
              <label>Layout<input value={draft.report_skeleton} disabled={!isAdmin} onChange={(e) => set("report_skeleton", e.target.value)} /></label>
              <label>Title<input value={draft.report_title} maxLength={120} disabled={!isAdmin} onChange={(e) => set("report_title", e.target.value)} /></label>
              <label>Classification<input value={draft.classification} maxLength={40} disabled={!isAdmin} onChange={(e) => set("classification", e.target.value)} /></label>
            </div>
            <div style={{ display: "flex", gap: 10, alignItems: "center", marginTop: 12, flexWrap: "wrap" }}>
              <button className="btn" disabled={!isAdmin || busy === "save"} onClick={() => void run("save", async () => { const v = await put<Settings>("/api/settings", draft); setDraft({ ...draft, updated_by: v.updated_by, updated_at: v.updated_at }); cfg.reload(); return "Settings saved."; })}>Save defaults</button>
              {!isAdmin && <span className="muted" style={{ fontSize: 12.5 }}><Lock size={12} style={{ verticalAlign: -1 }} /> Only an admin can change settings.</span>}
              {draft.updated_at && <span className="muted" style={{ fontSize: 12 }}>Last changed {ago(draft.updated_at)} by {draft.updated_by}</span>}
            </div>
          </>
        )}
      </Section>

      <div className="st-grid c2">
        <Section title="Guard" hint={guard.data?.reachable ? `mode ${guard.data.mode}` : "not reachable"}>
          <div className="seg" role="group" aria-label="Guard mode" style={{ marginBottom: 12 }}>
            {(["off", "monitor", "enforce"] as const).map((m) => (
              <button key={m} className={m} aria-pressed={guard.data?.mode === m} disabled={!canOperate || !guard.data?.reachable || busy === "mode"} onClick={() => void run("mode", async () => { await post("/api/guard/mode", { mode: m }); guard.reload(); return `Guard set to ${m}.`; })}>{m}</button>
            ))}
          </div>
          <div style={{ display: "grid", gap: 7 }}>
            {(pol.data?.all ?? Object.keys(DEFENSE)).map((d) => (
              <label key={d} className="ti-check" style={{ alignItems: "flex-start" }}>
                <input type="checkbox" checked={enabled.includes(d)} disabled={!canOperate} onChange={(e) => setEnabled(e.target.checked ? [...enabled, d] : enabled.filter((x) => x !== d))} />
                <span><b>{d} · {DEFENSE[d]?.[0] ?? d}</b><br /><span className="muted" style={{ fontSize: 12 }}>{DEFENSE[d]?.[1]}</span></span>
              </label>
            ))}
          </div>
          <button className="btn" style={{ marginTop: 12 }} disabled={!canOperate || busy === "policy"} onClick={() => void run("policy", async () => { await post("/api/guard/policy", { enabled }); pol.reload(); return "Defenses applied to the running guard."; })}>Apply defenses</button>
        </Section>

        <Section title="Threat intelligence" hint={intel.data ? `${intel.data.facets.total} records` : ""}>
          <table className="tbl"><thead><tr><th>Source</th><th>Records</th><th>Last sync</th><th>Key</th></tr></thead>
            <tbody>{sources.filter((s) => s.role !== "taxonomy").map((s) => <tr key={s.name}><td>{s.name}</td><td>{s.items}</td><td>{s.error ? <span style={{ color: "var(--breach)" }}>failed</span> : ago(s.last_sync)}</td><td className="muted">{s.key_env ? (s.key_set ? "set" : "not set (optional)") : "none needed"}</td></tr>)}</tbody></table>
          <p className="muted" style={{ fontSize: 12.5, margin: "10px 0" }}>Syncing is manual and audited; nothing is fetched during a test. Optional keys <code>AVHSOL_GITHUB_TOKEN</code> and <code>AVHSOL_NVD_API_KEY</code> raise rate limits.</p>
          <button className="btn ghost" disabled={!isAdmin || busy === "sync"} onClick={() => void run("sync", async () => { const r = await post<{ results: { source: string; added: number; error?: string }[] }>("/api/intel/sync", {}); intel.reload(); return "Sync finished: " + r.results.map((x) => `${x.source} ${x.error ? "failed" : `+${x.added}`}`).join(", "); })}><RefreshCw size={14} className={busy === "sync" ? "spin" : ""} /> Sync all sources</button>
          {!isAdmin && <span className="muted" style={{ fontSize: 12.5, marginLeft: 10 }}><Lock size={12} style={{ verticalAlign: -1 }} /> Admin only.</span>}
        </Section>
      </div>

      <div className="st-grid c2">
        <Section title="Sandbox" hint="what confines the agent under test">
          <table className="tbl"><tbody>
            <tr><td className="muted" style={{ width: 150 }}>Landlock</td><td>{status.data?.health.find((h) => h.id === "landlock")?.detail}</td></tr>
            <tr><td className="muted">gVisor</td><td>{status.data?.health.find((h) => h.id === "gvisor")?.detail}</td></tr>
            <tr><td className="muted">Limits</td><td style={{ fontSize: 13 }}>{status.data?.sys.sandbox.limits.note}</td></tr>
          </tbody></table>
        </Section>
        <Section title="Appearance" hint="this browser only">
          <label className="ti-check"><input type="checkbox" checked={reduce} onChange={(e) => { setReduce(e.target.checked); try { localStorage.setItem("avhsol.motion", e.target.checked ? "reduce" : ""); } catch { /* ignore */ } document.documentElement.dataset.motion = e.target.checked ? "reduce" : ""; }} /> Reduce motion (also follows your system setting)</label>
        </Section>
      </div>

      <Section title="Danger zone" hint="admin only, cannot be undone" danger>
        <p style={{ margin: "0 0 10px", fontSize: 13.5 }}><ShieldAlert size={14} style={{ verticalAlign: -2, color: "var(--breach)" }} /> Resetting the graph deletes every episode, step, verdict, intel node and vector. Recorded traces on disk are not touched, so the graph can be rebuilt with <code>avhsol graph ingest</code>.</p>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          <input value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder='Type RESET to confirm' aria-label="Type RESET to confirm" style={{ font: "inherit", padding: "8px 10px", borderRadius: 9, border: "1px solid var(--line-strong)", background: "rgba(5,9,18,0.8)", color: "var(--ink)" }} />
          <button className="btn ghost" disabled={!isAdmin || confirm !== "RESET" || busy === "reset"} onClick={() => void run("reset", async () => { await post("/api/graph/reset", { confirm }); setConfirm(""); return "Graph reset."; })}><Trash2 size={14} /> Reset the graph</button>
        </div>
      </Section>
    </div>
  );
}
