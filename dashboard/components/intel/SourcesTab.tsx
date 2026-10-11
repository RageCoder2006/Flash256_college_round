"use client";
import { useState } from "react";
import { CheckCircle2, CircleAlert, KeyRound, RefreshCw } from "lucide-react";
import { post, type IntelSources } from "@/lib/api";
import { ago } from "./shared";

const ROLE: Record<string, string> = { advisories: "Advisories", cves: "CVE records", enricher: "Enrichment", research: "Research", taxonomy: "Taxonomy" };

export function SourcesTab({ data, role, reload }: { data: IntelSources | null; role?: string; reload: () => void }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  async function sync(sources?: string[]) {
    setBusy(true);
    setMsg("Syncing. This can take several minutes because NVD limits how fast it can be queried.");
    try {
      const r = await post<{ results: { source: string; fetched: number; added: number; error?: string }[] }>("/api/intel/sync", { sources });
      setMsg(r.results.map((x) => `${x.source}: ${x.error ? "failed" : `${x.added} new`}`).join(" · "));
      reload();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  const f = data?.facets;
  const tiles: [string, string | number, string][] = f
    ? [
        ["Records in the cache", f.total, "#8f80ff"],
        ["Known exploited (KEV)", f.kev, "#ff5577"],
        ["Critical", f.severity.critical ?? 0, "#ff7a45"],
        ["High", f.severity.high ?? 0, "#ffb454"],
        ["Research papers", f.kinds.paper ?? 0, "#3fd0c9"],
        ["Taxonomy version", f.taxonomy_version || "n/a", "#4dd8ff"],
      ]
    : [];
  return (
    <div>
      <div className="stat-tiles">
        {tiles.map(([l, v, c]) => (
          <div key={l} className="stat-tile" style={{ ["--c" as string]: c }}><div className="v">{v}</div><div className="l">{l}</div></div>
        ))}
      </div>
      <div className="ti-bar">
        <p className="muted" style={{ margin: 0, maxWidth: 680 }}>
          Everything here comes from a local cache. Nothing is fetched while a test runs: syncing is an explicit action, recorded in the audit log, and
          the cache can also be loaded from a signed bundle on a machine with no network.
        </p>
        {role === "admin" ? (
          <button className="btn" disabled={busy} onClick={() => void sync()}><RefreshCw size={15} className={busy ? "spin" : ""} /> {busy ? "Syncing" : "Sync all sources"}</button>
        ) : (
          <span className="muted" style={{ fontSize: 12.5 }}>Only an admin can start a sync (<code>avhsol intel sync</code>).</span>
        )}
      </div>
      {msg && <div className="ti-msg" role="status">{msg}</div>}
      <div className="src-grid">
        {(data?.sources ?? []).map((s) => (
          <div key={s.name} className="src-card">
            <div className="src-top">
              <b>{s.title}</b>
              <span className="ti-pill" style={{ ["--c" as string]: "#4dd8ff" }}>{ROLE[s.role] ?? s.role}</span>
            </div>
            <p>{s.description}</p>
            <div className="src-stats">
              <div><span className="n">{s.items.toLocaleString()}</span><span className="muted">{s.role === "enricher" ? "items enriched" : "records"}</span></div>
              <div><span className="n sm">{ago(s.last_sync)}</span><span className="muted">last sync</span></div>
            </div>
            <div className="src-foot">
              {s.error ? (
                <span className="bad" title={s.error}><CircleAlert size={14} /> Last sync failed</span>
              ) : s.last_sync ? (
                <span className="ok"><CheckCircle2 size={14} /> Healthy</span>
              ) : (
                <span className="muted">Not synced yet</span>
              )}
              {s.key_env && (
                <span className="muted" title={`Set ${s.key_env} in the environment to raise the rate limit`}>
                  <KeyRound size={13} /> {s.key_set ? "API key set" : "No API key (optional)"}
                </span>
              )}
              <a href={s.url} target="_blank" rel="noopener noreferrer" className="muted">Visit</a>
              {role === "admin" && <button className="btn ghost sm" disabled={busy} onClick={() => void sync([s.name])}>Sync</button>}
            </div>
            {s.error && <div className="src-err">{s.error}</div>}
          </div>
        ))}
        <div className="src-card">
          <div className="src-top"><b>MITRE ATLAS · OWASP LLM · OWASP agentic</b><span className="ti-pill" style={{ ["--c" as string]: "#c9a8ff" }}>Taxonomy</span></div>
          <p>Static, versioned mapping from each attack technique AVHSOL knows to the ids used by these frameworks. Works offline; it is how advisories are matched to findings.</p>
          <div className="src-stats">
            <div><span className="n sm">{f?.taxonomy_version || "n/a"}</span><span className="muted">version</span></div>
            <div><span className="n">{Object.keys(f?.techniques ?? {}).length}</span><span className="muted">techniques seen in intel</span></div>
          </div>
        </div>
      </div>
    </div>
  );
}
