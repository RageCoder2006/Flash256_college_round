"use client";
import Link from "next/link";
import { useMemo, useState } from "react";
import { Activity, ExternalLink, OctagonX } from "lucide-react";
import { Area, Cores, Ring, Spark, Stack, Tile } from "@/components/charts/charts";
import { post } from "@/lib/api";
import { fmtBytes, fmtDur, fmtKB, fmtRate, useStatus, type Health } from "@/lib/status";
import { useFetch } from "@/lib/use";

const STATE_LABEL: Record<Health["state"], string> = { ok: "Healthy", warn: "Attention", bad: "Problem", off: "Not configured" };

export default function StatusPage() {
  const { snap, hist, live, error } = useStatus();
  const who = useFetch<{ role: string }>("/api/whoami");
  const [busy, setBusy] = useState(false);
  const s = snap?.sys;
  const h = s?.host;
  const series = (k: keyof (typeof hist)[number]) => hist.map((p) => Number(p[k]));
  const times = useMemo(() => hist.map((p) => p.t), [hist]);
  const canOperate = who.data?.role === "operator" || who.data?.role === "admin";

  async function cancel() {
    if (!snap?.run.id) return;
    setBusy(true);
    try { await post(`/api/runs/${snap.run.id}/cancel`, {}); } finally { setBusy(false); }
  }

  const worst = snap?.health.some((x) => x.state === "bad") ? "bad" : snap?.health.some((x) => x.state === "warn") ? "warn" : "ok";
  const mem = h?.mem;
  const memPct = mem && mem.total_kb ? (100 * mem.used_kb) / mem.total_kb : 0;
  const swapPct = mem && mem.swap_total_kb ? (100 * mem.swap_used_kb) / mem.swap_total_kb : 0;
  const rootDisk = h?.disks[0];
  const diskPct = (d?: { total_bytes: number; used_bytes: number }) => (d && d.total_bytes ? (100 * d.used_bytes) / d.total_bytes : 0);

  return (
    <div>
      <div className="page-head" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", gap: 12, flexWrap: "wrap" }}>
        <div>
          <h1>Status</h1>
          <p className="muted" style={{ margin: 0 }}>The test environment right now: the machine, the sandbox, the guard, and the run in progress.</p>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <span className={`live-pill${live ? "" : " off"}`} role="status"><i />{live ? "Live" : error ? "Reconnecting" : "Connecting"}</span>
          {typeof snap?.env.grafana === "string" && snap.env.grafana && <a className="btn ghost" href={snap.env.grafana} target="_blank" rel="noopener noreferrer"><ExternalLink size={14} /> Open Grafana</a>}
        </div>
      </div>

      {h && !h.supported && <div className="ti-msg bad">Host metrics are only available on Linux. Everything else on this page still works.</div>}

      {/* environment health */}
      <div className="panel" style={{ marginBottom: 14 }}>
        <h3>Environment <span>{worst === "ok" ? "everything configured is healthy" : worst === "warn" ? "something needs attention" : "something is broken"}</span></h3>
        <div className="hl">
          {(snap?.health ?? []).map((x) => (
            <div key={x.id} className={`hitem ${x.state}`} title={STATE_LABEL[x.state]}>
              <i className="dot" />
              <div><b>{x.label}{x.latency_ms ? <span style={{ marginLeft: 6 }}>{x.latency_ms.toFixed(0)} ms</span> : null}</b><span>{x.detail ?? STATE_LABEL[x.state]}</span></div>
            </div>
          ))}
          {!snap && <span className="muted">Connecting to the API…</span>}
        </div>
      </div>

      {/* headline tiles */}
      <div className="st-grid c4">
        <Tile label="CPU" value={h ? `${h.cpu_percent.toFixed(0)}%` : "…"} sub={h ? `${h.ncpu} cores · load ${h.load[0].toFixed(2)}` : ""} color="#4dd8ff" trend={series("cpu")} trendMax={100} />
        <Tile label="Memory" value={h ? `${memPct.toFixed(0)}%` : "…"} sub={mem ? `${fmtKB(mem.used_kb)} of ${fmtKB(mem.total_kb)}` : ""} color="#8f80ff" trend={series("mem")} trendMax={100} />
        <Tile label="Swap" value={mem && mem.swap_total_kb ? `${swapPct.toFixed(0)}%` : "none"} sub={mem && mem.swap_total_kb ? `${fmtKB(mem.swap_used_kb)} of ${fmtKB(mem.swap_total_kb)}` : ""} color="#ffb454" trend={series("swap")} trendMax={100} />
        <Tile label="Uptime" value={h ? fmtDur(h.uptime_sec) : "…"} sub={h?.cpu_model ? h.cpu_model.replace(/\(R\)|\(TM\)|CPU /g, "").slice(0, 40) : ""} color="#35e3ac" />
      </div>

      {/* host */}
      <div className="st-grid c2">
        <div className="panel">
          <h3>CPU <span>{h ? `${h.cpu_percent.toFixed(1)}% total${h.cpu_mhz ? ` · up to ${(h.cpu_mhz / 1000).toFixed(2)} GHz seen` : ""}` : ""}</span></h3>
          <Area series={[{ name: "CPU", color: "#4dd8ff", data: series("cpu") }, { name: "Load (1 min)", color: "#ffb454", data: series("load1"), dashed: true }]} times={times} yMax={Math.max(100, ...series("load1"))} fmt={(v) => v.toFixed(v < 10 ? 1 : 0)} />
          {h && <div style={{ marginTop: 10 }}><div className="muted" style={{ fontSize: 11.5, marginBottom: 4 }}>Per core</div><Cores values={h.cores} /></div>}
          {h && <div className="chart-legend" style={{ marginTop: 8 }}><span>Load <b>{h.load.map((x) => x.toFixed(2)).join(" · ")}</b></span>{h.psi.ok && <span>Pressure (CPU / mem / IO) <b>{h.psi.cpu.toFixed(1)} / {h.psi.mem.toFixed(1)} / {h.psi.io.toFixed(1)}%</b></span>}</div>}
        </div>
        <div className="panel">
          <h3>Memory and swap <span>{mem ? `${fmtKB(mem.available_kb)} available` : ""}</span></h3>
          <Area series={[{ name: "RAM used", color: "#8f80ff", data: series("mem") }, { name: "Swap used", color: "#ffb454", data: series("swap") }]} times={times} yMax={100} unit="%" />
          {mem && (
            <div style={{ marginTop: 10 }}>
              <Stack total={mem.total_kb} fmt={fmtKB} segs={[{ label: "In use", value: mem.used_kb - Math.min(mem.used_kb, mem.cached_kb * 0), color: "#8f80ff" }, { label: "Cache", value: mem.cached_kb + mem.buffers_kb, color: "#4dd8ff" }, { label: "Free", value: Math.max(0, mem.total_kb - mem.used_kb - mem.cached_kb - mem.buffers_kb), color: "rgba(130,160,230,0.25)" }]} />
              {mem.swap_total_kb > 0 && <div style={{ marginTop: 10 }}><Stack total={mem.swap_total_kb} fmt={fmtKB} segs={[{ label: "Swap used", value: mem.swap_used_kb, color: "#ffb454" }, { label: "Swap free", value: mem.swap_total_kb - mem.swap_used_kb, color: "rgba(130,160,230,0.25)" }]} /></div>}
            </div>
          )}
        </div>
      </div>

      <div className="st-grid c3">
        <div className="panel">
          <h3>Network <span>excluding loopback</span></h3>
          <Area series={[{ name: "Receive", color: "#35e3ac", data: series("rx") }, { name: "Send", color: "#ff5577", data: series("tx") }]} times={times} fmt={fmtRate} height={120} />
        </div>
        <div className="panel">
          <h3>Disk I/O</h3>
          <Area series={[{ name: "Read", color: "#4dd8ff", data: series("dr") }, { name: "Write", color: "#ffb454", data: series("dw") }]} times={times} fmt={fmtRate} height={120} />
        </div>
        <div className="panel">
          <h3>Storage and temperature</h3>
          <div style={{ display: "flex", gap: 14, flexWrap: "wrap", justifyContent: "space-around" }}>
            {(h?.disks ?? []).slice(0, 2).map((d, i) => (
              <Ring key={d.path} value={diskPct(d)} color={diskPct(d) > 90 ? "#ff5577" : diskPct(d) > 75 ? "#ffb454" : "#35e3ac"} label={i === 0 ? "System disk" : "Runs disk"} sub={`${fmtBytes(d.free_bytes)} free`} size={96} />
            ))}
          </div>
          {h?.temps && h.temps.length > 0 && (
            <div className="chart-legend" style={{ marginTop: 10 }}>
              {[...h.temps].sort((a, b) => b.c - a.c).slice(0, 4).map((t) => <span key={t.label}>{t.label} <b style={{ color: t.c > 85 ? "#ff5577" : t.c > 70 ? "#ffb454" : undefined }}>{t.c.toFixed(0)}°C</b></span>)}
            </div>
          )}
          {rootDisk && <p className="muted" style={{ fontSize: 11.5, margin: "8px 0 0" }}>Runs are written under {h?.disks[1]?.path ?? rootDisk.path}</p>}
        </div>
      </div>

      {/* sandbox */}
      <div className="st-grid c2">
        <div className="panel">
          <h3>Sandbox <span>{s?.sandbox.active ? `run in progress · ${s.sandbox.processes} process(es)` : "idle · nothing running"}</span></h3>
          <Area series={[{ name: "CPU of run (one core = 100%)", color: "#ff5577", data: series("sb_cpu") }]} times={times} height={110} unit="%" />
          <div className="st-grid c3" style={{ margin: "10px 0 0" }}>
            <Tile label="Memory in use" value={s ? fmtBytes(s.sandbox.rss_bytes) : "…"} sub={s ? (s.sandbox.limits.memory_bytes ? `limit ${fmtBytes(s.sandbox.limits.memory_bytes)}` : "no memory limit") : ""} color="#8f80ff" />
            <Tile label="Processes" value={s?.sandbox.processes ?? 0} sub={s ? `limit ${s.sandbox.limits.max_procs} · ${s.sandbox.threads} threads` : ""} color="#4dd8ff" />
            <Tile label="Isolation" value={s?.sandbox.limits.isolation ?? "…"} sub={s?.sandbox.limits.isolation === "landlock" ? "host kernel + seccomp" : "gVisor, no network"} color="#ffb454" />
          </div>
          {s?.sandbox.limits.note && <p className="muted" style={{ fontSize: 12, margin: "10px 0 0" }}>{s.sandbox.limits.note}.</p>}
          {s && s.sandbox.top && s.sandbox.top.length > 0 && (
            <table className="tbl" style={{ marginTop: 8 }}><thead><tr><th>Process</th><th>CPU</th><th>Memory</th><th>Threads</th></tr></thead>
              <tbody>{s.sandbox.top.map((p) => <tr key={p.pid}><td><code>{p.name}</code></td><td>{p.cpu_percent.toFixed(0)}%</td><td>{fmtBytes(p.rss_bytes)}</td><td>{p.threads}</td></tr>)}</tbody></table>
          )}
        </div>
        <div className="panel">
          <h3>Containers and services <span>{s?.containers?.length ? `${s.containers.length} running` : "docker not in use"}</span></h3>
          {!!s?.containers?.length && (
            <table className="tbl"><thead><tr><th>Name</th><th>CPU</th><th>Memory</th><th>PIDs</th></tr></thead>
              <tbody>{s.containers.map((c) => <tr key={c.name}><td><code>{c.name.replace("avhsol-", "")}</code>{c.kind === "episode" && <span className="ti-pill" style={{ ["--c" as string]: "#ffb454", marginLeft: 6 }}>sandbox</span>}</td><td>{c.cpu_percent.toFixed(1)}%</td><td>{fmtBytes(c.mem_bytes)}{c.mem_limit_bytes ? ` / ${fmtBytes(c.mem_limit_bytes)}` : ""}</td><td>{c.pids}</td></tr>)}</tbody></table>
          )}
          <table className="tbl" style={{ marginTop: 10 }}><thead><tr><th>AVHSOL component</th><th>CPU</th><th>Memory</th><th>Threads</th><th>FDs</th></tr></thead>
            <tbody>{(s?.procs ?? []).map((p) => <tr key={p.pid}><td>{p.component}</td><td>{p.cpu_percent.toFixed(1)}%</td><td>{fmtBytes(p.rss_bytes)}</td><td>{p.threads}</td><td>{p.fds}</td></tr>)}</tbody></table>
        </div>
      </div>

      {/* run + guard + environment */}
      <div className="st-grid c2">
        <div className="panel">
          <h3>Run activity <span>{snap?.run.status === "running" ? `${snap.run.kind} · ${fmtDur(snap.run.elapsed_sec ?? 0)}` : snap?.run.status ?? ""}</span></h3>
          <div className="st-grid c4" style={{ margin: "0 0 10px" }}>
            <Tile label="Attack runs" value={snap?.traces.attacks ?? 0} sub={`${snap?.traces.valid_attacks ?? 0} valid`} color="#ff5577" />
            <Tile label="Exploited" value={snap?.traces.exploits ?? 0} sub={snap && snap.traces.valid_attacks ? `${Math.round((100 * snap.traces.exploits) / snap.traces.valid_attacks)}% of valid` : ""} color="#ffb454" />
            <Tile label="Benign runs" value={snap?.traces.benign ?? 0} color="#35e3ac" />
            <Tile label="Errored" value={snap?.traces.errored ?? 0} sub={snap?.traces.simulated ? `${snap.traces.simulated} simulated` : "excluded from rates"} color="#8a9cc4" />
          </div>
          {snap?.run.status === "running" && canOperate && (
            <button className="btn ghost" onClick={() => void cancel()} disabled={busy} style={{ marginBottom: 8 }}><OctagonX size={14} /> Cancel the run</button>
          )}
          {snap?.run.tail && snap.run.tail.length > 0 ? <div className="logtail" aria-live="off">{snap.run.tail.join("\n")}</div> : <p className="muted" style={{ margin: 0, fontSize: 13 }}>No run is active. Start one from <Link href="/console/run" style={{ color: "var(--cyan)" }}>Run</Link>.</p>}
        </div>
        <div className="panel">
          <h3>Guard and test environment <span>{snap?.guard ? `mode ${snap.guard.mode}` : "guard not reachable"}</span></h3>
          {snap?.guard && (
            <>
              <div className="st-grid c4" style={{ margin: "0 0 10px" }}>
                <Tile label="Allowed" value={snap.guard.decisions.allow ?? 0} color="#35e3ac" />
                <Tile label="Denied" value={snap.guard.decisions.deny ?? 0} color="#ff5577" />
                <Tile label="Decision p50" value={`${(snap.guard.decision_latency_us.p50 / 1000).toFixed(1)} ms`} sub={`p99 ${(snap.guard.decision_latency_us.p99 / 1000).toFixed(1)} ms`} color="#4dd8ff" />
                <Tile label="Model wait p50" value={snap.guard.upstream_wait_us ? `${(snap.guard.upstream_wait_us.p50 / 1e6).toFixed(1)} s` : "n/a"} sub="model latency, not guard" color="#8f80ff" />
              </div>
              {Object.keys(snap.guard.by_rule).length > 0 && <div className="chart-legend" style={{ marginBottom: 10 }}>{Object.entries(snap.guard.by_rule).map(([r, n]) => <span key={r}>{r} <b>{n}</b></span>)}</div>}
            </>
          )}
          <table className="tbl"><tbody>
            {[["Model", snap?.env.model ?? "not configured"], ["Scenario", snap?.env.scenario], ["Seeds", snap?.env.seeds], ["Target", snap?.env.target || "simulated-tool harness"], ["Isolation default", snap?.env.isolation], ["Guard default", snap?.env.guard_default], ["Graph", snap?.env.graph ? "connected" : "off"], ["Runtime", `${snap?.env.go ?? ""} · ${snap?.env.os ?? ""}`]].map(([k, v]) => (
              <tr key={String(k)}><td className="muted" style={{ width: 130 }}>{k}</td><td>{String(v ?? "")}</td></tr>
            ))}
          </tbody></table>
        </div>
      </div>
      <p className="muted" style={{ fontSize: 12 }}><Activity size={12} style={{ verticalAlign: -1 }} /> Updated every {String(snap?.env.refresh_sec ?? 2)} s from this machine&apos;s /proc and the processes AVHSOL started. History is kept for 30 minutes while the API runs; Prometheus and Grafana keep it longer (see About).</p>
    </div>
  );
}
