"use client";
import { useEffect, useMemo, useState } from "react";
import { Search, Sparkles } from "lucide-react";
import { get, type IntelHit, type IntelItem, type IntelSearch, type IntelSources } from "@/lib/api";
import { ItemDetail, SevPill } from "./shared";

export function BrowseTab({ meta }: { meta: IntelSources | null }) {
  const [q, setQ] = useState("");
  const [submitted, setSubmitted] = useState("");
  const [source, setSource] = useState("");
  const [kind, setKind] = useState("");
  const [tag, setTag] = useState("");
  const [kev, setKev] = useState(false);
  const [items, setItems] = useState<(IntelItem | IntelHit)[]>([]);
  const [semantic, setSemantic] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [picked, setPicked] = useState<IntelItem | null>(null);

  const sources = useMemo(() => (meta?.sources ?? []).filter((s) => s.role !== "enricher").map((s) => s.name), [meta]);
  const techniques = useMemo(() => Object.entries(meta?.facets.techniques ?? {}).sort((a, b) => b[1] - a[1]), [meta]);

  useEffect(() => {
    let live = true;
    setBusy(true);
    setErr("");
    const run = async () => {
      try {
        if (submitted) {
          const r = await get<IntelSearch>(`/api/intel/search?q=${encodeURIComponent(submitted)}`);
          if (!live) return;
          setSemantic(r.semantic);
          setItems(r.hits.filter((h) => (!source || h.source === source || (source === "feeds" && h.source.startsWith("feed:"))) && (!kind || h.kind === kind) && (!kev || h.kev) && (!tag || h.tags?.includes("technique:" + tag))));
        } else {
          const p = new URLSearchParams({ n: "60" });
          if (source) p.set("source", source);
          if (kind) p.set("kind", kind);
          if (tag) p.set("tag", "technique:" + tag);
          if (kev) p.set("kev", "1");
          const r = await get<IntelItem[]>(`/api/intel/items?${p}`);
          if (live) setItems(r);
        }
      } catch (e) {
        if (live) setErr(e instanceof Error ? e.message : String(e));
      } finally {
        if (live) setBusy(false);
      }
    };
    void run();
    return () => { live = false; };
  }, [submitted, source, kind, tag, kev]);

  return (
    <div className="ti-split">
      <div>
        <form className="ti-search" onSubmit={(e) => { e.preventDefault(); setSubmitted(q.trim()); }}>
          <Search size={16} aria-hidden="true" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Ask the data sources: “MCP server command injection”, “prompt injection in coding assistants”…" aria-label="Search threat intelligence" />
          <button className="btn" disabled={busy}>Search</button>
          {submitted && <button type="button" className="btn ghost" onClick={() => { setQ(""); setSubmitted(""); }}>Clear</button>}
        </form>
        <div className="ti-filters">
          <select value={source} onChange={(e) => setSource(e.target.value)} aria-label="Source"><option value="">All sources</option>{sources.map((s) => <option key={s}>{s}</option>)}</select>
          <select value={kind} onChange={(e) => setKind(e.target.value)} aria-label="Kind"><option value="">All kinds</option><option value="advisory">Advisories</option><option value="cve">CVEs</option><option value="paper">Papers</option></select>
          <select value={tag} onChange={(e) => setTag(e.target.value)} aria-label="Attack technique"><option value="">Any technique</option>{techniques.map(([t, n]) => <option key={t} value={t}>{t.replace(/_/g, " ")} ({n})</option>)}</select>
          <label className="ti-check"><input type="checkbox" checked={kev} onChange={(e) => setKev(e.target.checked)} /> Exploited only</label>
        </div>
        {submitted && (
          <p className="muted" style={{ fontSize: 12.5, margin: "6px 2px" }}>
            {semantic ? <><Sparkles size={12} style={{ verticalAlign: -1 }} /> Matches by meaning come first, then by text.</> : "Text match only (the vector store is not connected)."}
          </p>
        )}
        {err && <div className="ti-msg bad">{err}</div>}
        <div className="ti-list" aria-busy={busy}>
          {items.map((it) => (
            <button key={it.source + it.id} className={`ti-row${picked?.id === it.id && picked.source === it.source ? " on" : ""}`} onClick={() => setPicked(it)}>
              <code>{it.id}</code>
              <span className="t">{it.title}</span>
              <span className="meta"><SevPill it={it} /><span className="muted">{it.source.replace("feed:", "")}</span>{"via" in it && it.via === "meaning" && <span className="ti-pill" style={{ ["--c" as string]: "#8f80ff" }}>by meaning</span>}</span>
            </button>
          ))}
          {!items.length && !busy && <div className="muted" style={{ padding: 18 }}>{meta && meta.facets.total === 0 ? <>The cache is empty. Run <code>avhsol intel sync</code> or sync from the Sources tab.</> : "Nothing matches. Loosen the filters or rephrase the question."}</div>}
        </div>
      </div>
      <aside className="ti-detail glass">{picked ? <ItemDetail it={picked} /> : <div className="ins-empty muted">Pick a record to see its full details, affected packages, mapped taxonomy and a link to the original source.</div>}</aside>
    </div>
  );
}
