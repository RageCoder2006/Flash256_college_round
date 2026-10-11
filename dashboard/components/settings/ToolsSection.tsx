"use client";
import { useEffect, useMemo, useState } from "react";
import { Check, Copy, Lock, PlugZap } from "lucide-react";
import { put, type Settings, type ToolsResp, type PlatformTool } from "@/lib/api";
import { useFetch } from "@/lib/use";

const EFFECT: Record<string, { label: string; note: string; color: string }> = {
  read: { label: "Reads", note: "Reads files and returns text. Changes nothing.", color: "var(--ok, #35d0a0)" },
  writes: { label: "Writes", note: "Writes a report or file inside AVHSOL's own directories.", color: "var(--warn, #f0b84a)" },
  launches: { label: "Launches", note: "Starts agents or attacks. Runs the audited agent's code in a sandbox.", color: "var(--breach, #ff5577)" },
};

function CopyLine({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <div style={{ display: "flex", gap: 8, alignItems: "center", margin: "6px 0" }}>
      <code style={{ flex: 1, overflowX: "auto", whiteSpace: "nowrap", padding: "7px 10px", borderRadius: 8, background: "rgba(5,9,18,0.8)", border: "1px solid var(--line)" }}>{text}</code>
      <button className="btn ghost" aria-label="Copy command" onClick={() => { void navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1500); }).catch(() => undefined); }}>{done ? <Check size={14} /> : <Copy size={14} />}</button>
    </div>
  );
}

/** Every tool the platform has, in a drop-down, with the switch that serves it to Claude Code or another MCP client. */
export function ToolsSection({ draft, isAdmin, onSaved }: { draft: Settings | null; isAdmin: boolean; onSaved: (msg: string, bad?: boolean) => void }) {
  const tools = useFetch<ToolsResp>("/api/tools");
  const [pick, setPick] = useState("");
  const [enabled, setEnabled] = useState(false);
  const [allowed, setAllowed] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!tools.data) return;
    setEnabled(tools.data.mcp_enabled);
    setAllowed(Object.fromEntries(tools.data.tools.map((t) => [t.name, t.mcp_allowed])));
    setPick((p) => p || tools.data!.tools[0]?.name || "");
  }, [tools.data]);

  const groups = useMemo(() => {
    const g: Record<string, PlatformTool[]> = { read: [], writes: [], launches: [] };
    for (const t of tools.data?.tools ?? []) g[t.effect]?.push(t);
    return g;
  }, [tools.data]);
  const cur = tools.data?.tools.find((t) => t.name === pick);
  const props = Object.entries(cur?.input_schema.properties ?? {});
  const total = tools.data?.tools.length ?? 0;

  const save = async () => {
    if (!draft) return;
    setBusy(true);
    try {
      await put<Settings>("/api/settings", { ...draft, mcp_enabled: enabled, mcp_tools: Object.keys(allowed).filter((k) => allowed[k]) });
      tools.reload();
      onSaved(enabled ? "MCP endpoint is on with the selected tools." : "MCP endpoint is off.");
    } catch (e) { onSaved(e instanceof Error ? e.message : String(e), true); } finally { setBusy(false); }
  };

  return (
    <section className="panel" style={{ marginBottom: 14 }}>
      <h3>Tools<span>{total} in this platform</span></h3>
      <label style={{ display: "block", maxWidth: 520 }}>
        <span className="muted" style={{ fontSize: 12.5 }}>Choose a tool to see what it does</span>
        <select value={pick} onChange={(e) => setPick(e.target.value)} aria-label="Platform tools" style={{ width: "100%", marginTop: 4 }}>
          {(["read", "writes", "launches"] as const).map((k) => groups[k].length > 0 && (
            <optgroup key={k} label={`${EFFECT[k].label} (${groups[k].length})`}>
              {groups[k].map((t) => <option key={t.name} value={t.name}>{t.name}  ·  {t.title}</option>)}
            </optgroup>
          ))}
        </select>
      </label>
      {tools.error && <p className="muted" style={{ color: "var(--breach)" }}>Could not load the tool list: {String(tools.error)}</p>}
      {cur && (
        <div style={{ marginTop: 14 }}>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center", marginBottom: 6 }}>
            <strong>{cur.title}</strong>
            <span style={{ fontSize: 12, padding: "2px 8px", borderRadius: 99, border: `1px solid ${EFFECT[cur.effect].color}`, color: EFFECT[cur.effect].color }}>{EFFECT[cur.effect].label}</span>
            <span className="muted" style={{ fontSize: 12.5 }}>needs role {cur.role}</span>
            <span className="muted" style={{ fontSize: 12.5 }}>{cur.mcp_exposed ? "served over MCP" : allowed[cur.name] ? "allowed, endpoint off" : "not served over MCP"}</span>
          </div>
          <p style={{ margin: "0 0 8px", fontSize: 13.5 }}>{cur.description}</p>
          <p className="muted" style={{ margin: "0 0 8px", fontSize: 12.5 }}>{EFFECT[cur.effect].note}</p>
          {props.length > 0 ? (
            <table className="tbl"><thead><tr><th>Argument</th><th>Type</th><th>Meaning</th></tr></thead>
              <tbody>{props.map(([k, v]) => <tr key={k}><td><code>{k}</code>{cur.input_schema.required?.includes(k) ? " *" : ""}</td><td>{v.enum ? v.enum.join(" | ") : v.type}</td><td>{v.description}</td></tr>)}</tbody></table>
          ) : <p className="muted" style={{ fontSize: 12.5 }}>Takes no arguments.</p>}
        </div>
      )}

      <h4 style={{ margin: "22px 0 6px", display: "flex", alignItems: "center", gap: 8 }}><PlugZap size={16} /> Use AVHSOL from Claude Code or another harness</h4>
      <p className="muted" style={{ fontSize: 13, margin: "0 0 6px" }}>Local, with your own user: run this once. It needs no switch here.</p>
      <CopyLine text={tools.data?.connect.stdio ?? "claude mcp add avhsol -- avhsol mcp"} />
      <p className="muted" style={{ fontSize: 13, margin: "10px 0 6px" }}>Over HTTP, with an API token (viewer, analyst or operator decides what the client can call). Needs the switch below.</p>
      <CopyLine text={tools.data?.connect.http ?? ""} />

      <label className="ti-check" style={{ marginTop: 12 }}><input type="checkbox" checked={enabled} disabled={!isAdmin} onChange={(e) => setEnabled(e.target.checked)} /> Serve the selected tools at <code>/mcp</code></label>
      {enabled && (
        <div style={{ margin: "10px 0", display: "grid", gap: 4, gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))" }}>
          {(tools.data?.tools ?? []).map((t) => (
            <label key={t.name} className="ti-check" style={{ fontSize: 13 }}>
              <input type="checkbox" checked={!!allowed[t.name]} disabled={!isAdmin} onChange={(e) => setAllowed({ ...allowed, [t.name]: e.target.checked })} /> {t.name}
              {t.effect === "launches" && <span style={{ color: "var(--breach)", marginLeft: 6 }}>launches</span>}
            </label>
          ))}
        </div>
      )}
      {enabled && Object.entries(allowed).some(([n, on]) => on && tools.data?.tools.find((t) => t.name === n)?.effect === "launches") && (
        <p style={{ fontSize: 13, color: "var(--breach)", margin: "6px 0" }}>A connected client with the operator role could start attacks and run the audited agent&apos;s code. Only allow this for clients you trust.</p>
      )}
      <div style={{ marginTop: 10, display: "flex", gap: 10, alignItems: "center" }}>
        <button className="btn" disabled={!isAdmin || !draft || busy} onClick={() => void save()}>Save MCP settings</button>
        {!isAdmin && <span className="muted" style={{ fontSize: 12.5 }}><Lock size={12} style={{ verticalAlign: -1 }} /> Admin only.</span>}
      </div>
    </section>
  );
}
