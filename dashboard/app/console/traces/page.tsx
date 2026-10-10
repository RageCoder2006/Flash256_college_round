"use client";
import Link from "next/link";
import { useState } from "react";
import type { TraceSummary } from "@/lib/api";
import { useFetch } from "@/lib/use";

export default function Traces() {
  const [kind, setKind] = useState("");
  const [guard, setGuard] = useState("");
  const { data, error } = useFetch<TraceSummary[]>(`/api/traces${kind ? `?kind=${kind}` : ""}`, 5000);
  const rows = (data ?? []).filter((t) => !guard || t.guard_mode === guard);
  return (
    <section className="section">
      <header><h2>Traces</h2><span className="sub">{rows.length} shown. Every step is hash-chained, so a trace can be replayed and checked.</span></header>
      <div className="filters">
        <div className="seg" role="group" aria-label="Kind">
          {[["", "All"], ["attack", "Attacks"], ["benign", "Benign tasks"]].map(([v, l]) => (
            <button key={v} aria-pressed={kind === v} onClick={() => setKind(v)}>{l}</button>
          ))}
        </div>
        <div className="seg" role="group" aria-label="Guard mode">
          {[["", "Any guard"], ["off", "Off"], ["enforce", "Enforcing"]].map(([v, l]) => (
            <button key={v} aria-pressed={guard === v} onClick={() => setGuard(v)}>{l}</button>
          ))}
        </div>
      </div>
      {error && <p className="err">{error}</p>}
      {!error && rows.length === 0 && <div className="empty">No traces match. Start a run to record some.</div>}
      {rows.length > 0 && (
        <div className="card" style={{ overflowX: "auto" }}>
          <table>
            <thead><tr><th>Trace</th><th>What</th><th>Guard</th><th>Outcome</th><th className="num">Progress</th><th className="num">Steps</th></tr></thead>
            <tbody>
              {rows.map((t) => (
                <tr key={t.id}>
                  <td><Link href={`/console/traces/${t.id}`} className="mono">{t.id}</Link></td>
                  <td>{t.kind === "attack" ? `${(t.technique ?? "").replaceAll("_", " ")} · ${t.surface}${t.operator && t.operator !== "none" ? ` · ${t.operator}` : ""}` : "benign task"}</td>
                  <td><span className="mono">{t.guard_mode}</span></td>
                  <td>
                    {t.kind === "attack"
                      ? <span className={`pill ${t.success ? "breach" : "held"}`}>{t.success ? "data leaked" : "contained"}</span>
                      : <span className={`pill ${t.success ? "held" : "breach"}`}>{t.success ? "completed" : "failed"}</span>}
                  </td>
                  <td className="num">{t.kind === "attack" ? `${t.progress}/5` : "–"}</td>
                  <td className="num">{t.steps}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
