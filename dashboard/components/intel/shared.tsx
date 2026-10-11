"use client";
import { ExternalLink, Flame } from "lucide-react";
import type { IntelItem } from "@/lib/api";

export function sevColor(s?: string): string {
  return ({ critical: "#ff7a45", high: "#ffb454", medium: "#ffd447", low: "#8a9cc4" } as Record<string, string>)[s ?? ""] ?? "#5b8cff";
}

export function ago(iso?: string): string {
  if (!iso) return "never";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (!isFinite(s)) return iso;
  if (s < 90) return "just now";
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 129600) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}

export function SevPill({ it }: { it: Pick<IntelItem, "severity" | "kev" | "kind"> }) {
  if (it.kind === "paper") return <span className="ti-pill" style={{ ["--c" as string]: "#3fd0c9" }}>paper</span>;
  return (
    <>
      {it.kev && <span className="ti-pill kev" title="Known to be exploited in the wild (CISA KEV)"><Flame size={11} /> exploited</span>}
      <span className="ti-pill" style={{ ["--c" as string]: sevColor(it.severity) }}>{it.severity || "unrated"}</span>
    </>
  );
}

/** Everything known about one item. All text is third-party data: React escapes it, and links open without referrer. */
export function ItemDetail({ it }: { it: IntelItem }) {
  const techs = (it.tags ?? []).filter((t) => t.startsWith("technique:")).map((t) => t.slice(10).replace(/_/g, " "));
  return (
    <div className="ins">
      <div className="ins-head">
        <i style={{ background: sevColor(it.severity), boxShadow: `0 0 10px ${sevColor(it.severity)}` }} />
        <div><small>{it.source} · {it.kind}</small><h3>{it.id}</h3></div>
      </div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8 }}><SevPill it={it} /></div>
      <p className="ins-note" style={{ borderColor: sevColor(it.severity) }}>{it.title}</p>
      {it.summary && it.summary !== it.title && <p className="muted" style={{ fontSize: 13, lineHeight: 1.55, margin: "0 0 10px" }}>{it.summary}</p>}
      <Row k="CVSS" v={it.cvss ? it.cvss.toFixed(1) : undefined} />
      <Row k="Exploit chance" v={it.epss ? `${(it.epss * 100).toFixed(1)}% in 30 days (EPSS)` : undefined} />
      <Row k="Published" v={it.published?.slice(0, 10)} />
      <Row k="Updated" v={it.modified?.slice(0, 10)} />
      <Row k="Also known as" v={it.aliases?.join(", ")} />
      <Row k="Affects" v={it.affects?.join(", ")} />
      <Row k="Attack techniques" v={techs.join(", ")} />
      <Row k="Taxonomy" v={it.taxon?.join(", ")} />
      {it.url && (
        <a className="btn ghost" style={{ marginTop: 12, display: "inline-flex", gap: 6 }} href={it.url} target="_blank" rel="noopener noreferrer nofollow">
          <ExternalLink size={14} /> Open the source record
        </a>
      )}
    </div>
  );
}

function Row({ k, v }: { k: string; v?: string }) {
  if (!v) return null;
  return <div className="ins-row"><span>{k}</span><b>{v}</b></div>;
}
