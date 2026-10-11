"use client";
import Link from "next/link";
import { CheckCircle2, CircleDashed, CircleDot } from "lucide-react";
import { ArchDiagram } from "@/components/ArchDiagram";
import { Logo } from "@/components/Logo";
import { KEY_FEATURES } from "@/lib/keyfeatures";
import { useFetch } from "@/lib/use";

interface About { name: string; expansion: string; version: string; authors: string[]; tagline: string; components: Record<string, string>; started_at: string; licences: { name: string; licence: string; url: string }[] }

const DOCS = [["Key features coverage", "KEY-FEATURES.md"], ["Status", "STATUS.md"], ["Roadmap", "ROADMAP.md"], ["Architecture", "ARCHITECTURE.md"], ["Threat intelligence", "INTEL.md"], ["Connectors", "CONNECTORS.md"], ["Sandbox", "SANDBOX.md"], ["Live revive", "REVIVE.md"], ["Monitoring", "MONITORING.md"], ["Reports", "REPORTS.md"], ["Security", "SECURITY.md"], ["Operations", "OPERATIONS.md"]];

export default function AboutPage() {
  const about = useFetch<About>("/api/about");
  const a = about.data;
  const icon = { done: <CheckCircle2 size={16} color="#35e3ac" />, partial: <CircleDot size={16} color="#ffb454" />, gap: <CircleDashed size={16} color="#ff5577" /> };
  return (
    <div>
      <div className="page-head" style={{ display: "flex", gap: 16, alignItems: "center" }}>
        <Logo size={52} />
        <div><h1 style={{ margin: 0 }}>{a?.name ?? "AVHSOL"}</h1><p className="muted" style={{ margin: 0 }}>{a?.expansion ?? "Agentic Vulnerability Hunter with Simulated Offensive Layers"} · version {a?.version ?? "…"}</p></div>
      </div>

      <div className="st-grid c2">
        <section className="panel">
          <h3>What it is</h3>
          <p style={{ margin: "0 0 10px", lineHeight: 1.6, fontSize: 14.5 }}>AVHSOL is an autonomous red team for AI agents. It attacks an agent through the content it reads, proves what worked with deterministic checks and a signed, replayable trace, shows whether a guard stops the same attack without breaking normal work, and keeps everything in a bitemporal graph a security team can question, correct, replay and fork. Public threat intelligence feeds its attacks, its graph and its reports.</p>
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>Made by {a?.authors.join(" and ") ?? "David Porathur and Rishit Baitule"}. Built for BitNBuild.</p>
        </section>
        <section className="panel">
          <h3>This installation</h3>
          <table className="tbl"><tbody>
            {Object.entries(a?.components ?? {}).map(([k, v]) => <tr key={k}><td className="muted" style={{ width: 110 }}>{k}</td><td>{v}</td></tr>)}
            <tr><td className="muted">API started</td><td>{a?.started_at ? new Date(a.started_at).toLocaleString() : "…"}</td></tr>
          </tbody></table>
        </section>
      </div>

      <section className="panel" style={{ marginBottom: 14 }}>
        <h3>Key features, and how far each goes <span>an honest account</span></h3>
        <table className="tbl"><tbody>
          {KEY_FEATURES.map((k) => (
            <tr key={k.name}>
              <td style={{ width: 24, verticalAlign: "top" }}>{icon[k.state]}</td>
              <td style={{ width: 230, verticalAlign: "top" }}><b>{k.name}</b><div className="muted" style={{ fontSize: 11.5 }}>{k.state === "done" ? "Done" : k.state === "partial" ? "Partly done" : "Not built"}</div></td>
              <td style={{ fontSize: 13, lineHeight: 1.5 }}>{k.how}{k.gap && <div className="muted" style={{ marginTop: 3 }}>Gap: {k.gap}</div>}</td>
            </tr>
          ))}
        </tbody></table>
      </section>

      <section className="panel" style={{ marginBottom: 14 }}>
        <h3>Architecture</h3>
        <ArchDiagram id="about-arch" />
      </section>

      <div className="st-grid c2">
        <section className="panel">
          <h3>How a result is decided</h3>
          <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 6, fontSize: 13.5, color: "var(--ink-2)", lineHeight: 1.5 }}>
            <li>Success is a fact about the world (a planted canary reached a server, a host file was read), never the model&apos;s say-so.</li>
            <li>A no-attack control sits beside every result, because the model sometimes reads credentials unprompted.</li>
            <li>Errored runs are excluded and listed, never counted as defended. Simulated runs are labelled and never rated.</li>
            <li>A rating needs repeated runs; intel and research never change it.</li>
          </ul>
        </section>
        <section className="panel">
          <h3>Security of the platform</h3>
          <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 6, fontSize: 13.5, color: "var(--ink-2)", lineHeight: 1.5 }}>
            <li>Loopback-only services; viewer, analyst, operator and admin tokens compared in constant time; failed-login throttling.</li>
            <li>A hash-chained audit log of every state-changing request, including intel syncs and setting changes.</li>
            <li>Traces and intel bundles are signed; secrets are reduced to fingerprints before storage.</li>
            <li>Third-party text is cleaned, escaped and treated as data. Report previews run in a sandboxed frame.</li>
          </ul>
        </section>
      </div>

      <div className="st-grid c2">
        <section className="panel">
          <h3>Keyboard</h3>
          <table className="tbl"><tbody>
            <tr><td><code>↑ ↓</code> / <code>PgUp PgDn</code></td><td>Move between sections on the home page</td></tr>
            <tr><td><code>N</code></td><td>Speaker notes on the home page</td></tr>
            <tr><td><code>Esc</code></td><td>Close a report preview</td></tr>
            <tr><td><code>Enter</code></td><td>Send a question in the graph chat</td></tr>
          </tbody></table>
        </section>
        <section className="panel">
          <h3>Credits and licences</h3>
          <table className="tbl"><tbody>{(a?.licences ?? []).map((l) => <tr key={l.name}><td>{l.url ? <a href={l.url} target="_blank" rel="noopener noreferrer" style={{ color: "var(--cyan)" }}>{l.name}</a> : l.name}</td><td className="muted">{l.licence}</td></tr>)}</tbody></table>
          <p className="muted" style={{ fontSize: 12, margin: "8px 0 0" }}>Because ported detectors are GPLv3, AVHSOL is distributed under GPLv3.</p>
        </section>
      </div>

      <section className="panel">
        <h3>Documentation <span>the docs/ folder in the repository</span></h3>
        <div className="suggest" style={{ margin: 0 }}>{DOCS.map(([l, f]) => <span key={f} className="ti-pill" style={{ ["--c" as string]: "#4dd8ff" }}>{l} · docs/{f}</span>)}</div>
        <p className="muted" style={{ fontSize: 12.5, margin: "10px 0 0" }}>Open the repository&apos;s <code>docs/</code> folder, or see the project overview on the <Link href="/" style={{ color: "var(--cyan)" }}>home page</Link>.</p>
      </section>
    </div>
  );
}
