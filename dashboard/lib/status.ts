import { useEffect, useRef, useState } from "react";
import { get, streamEvents } from "./api";

export interface Host {
  at_ms: number; supported: boolean; ncpu: number; cpu_model?: string; cpu_mhz?: number; cpu_percent: number; cores: number[];
  load: [number, number, number]; uptime_sec: number;
  mem: { total_kb: number; available_kb: number; used_kb: number; cached_kb: number; buffers_kb: number; free_kb: number; dirty_kb: number; swap_total_kb: number; swap_used_kb: number };
  psi: { cpu: number; mem: number; io: number; ok: boolean };
  disks: { path: string; total_bytes: number; used_bytes: number; free_bytes: number }[];
  disk_read_bps: number; disk_write_bps: number; net_rx_bps: number; net_tx_bps: number;
  temps?: { label: string; c: number }[];
}
export interface Proc { component: string; name: string; pid: number; rss_bytes: number; cpu_percent: number; threads: number; fds: number }
export interface SandboxStat {
  active: boolean; root_pid?: number; processes: number; rss_bytes: number; cpu_percent: number; threads: number; top?: Proc[];
  limits: { isolation: string; max_procs: number; memory_bytes: number; cpu_seconds: number; note?: string };
}
export interface Container { name: string; cpu_percent: number; mem_bytes: number; mem_limit_bytes: number; mem_percent: number; pids: number; net_io?: string; kind: string }
export interface Health { id: string; label: string; state: "ok" | "warn" | "bad" | "off"; detail?: string; latency_ms?: number }
export interface RunInfo { id?: string; kind?: string; status: string; started_at?: string; elapsed_sec?: number; tail?: string[]; lines?: number }
export interface StatusSnapshot {
  at: number;
  sys: { host: Host; procs: Proc[]; sandbox: SandboxStat; containers: Container[] };
  health: Health[];
  run: RunInfo;
  traces: { total: number; attacks: number; benign: number; valid_attacks: number; exploits: number; errored: number; simulated: number };
  env: Record<string, string | boolean | number>;
  guard?: { mode: string; decisions: Record<string, number>; by_rule: Record<string, number>; decision_latency_us: { p50: number; p99: number; n: number }; upstream_wait_us?: { p50: number; p99: number; n: number } };
}
export interface HistPoint { t: number; cpu: number; mem: number; swap: number; load1: number; rx: number; tx: number; dr: number; dw: number; sb_cpu: number; sb_rss: number; sb_procs: number; psi_cpu: number; psi_mem: number; psi_io: number }

export function compact(s: StatusSnapshot["sys"]): HistPoint {
  const h = s.host;
  return {
    t: h.at_ms, cpu: h.cpu_percent, mem: h.mem.total_kb ? (100 * h.mem.used_kb) / h.mem.total_kb : 0, swap: h.mem.swap_total_kb ? (100 * h.mem.swap_used_kb) / h.mem.swap_total_kb : 0,
    load1: h.load[0], rx: h.net_rx_bps, tx: h.net_tx_bps, dr: h.disk_read_bps, dw: h.disk_write_bps,
    sb_cpu: s.sandbox.cpu_percent, sb_rss: s.sandbox.rss_bytes, sb_procs: s.sandbox.processes, psi_cpu: h.psi.cpu, psi_mem: h.psi.mem, psi_io: h.psi.io,
  };
}

const MAX_POINTS = 450;

/** Live status: history first, then a server-sent-event stream that reconnects on failure. */
export function useStatus() {
  const [snap, setSnap] = useState<StatusSnapshot | null>(null);
  const [hist, setHist] = useState<HistPoint[]>([]);
  const [live, setLive] = useState(false);
  const [error, setError] = useState("");
  const gen = useRef(0);
  useEffect(() => {
    const my = ++gen.current;
    const ctl = new AbortController();
    let stopped = false;
    (async () => {
      try {
        const h = await get<HistPoint[]>("/api/status/history?seconds=900");
        if (!stopped && my === gen.current) setHist(h ?? []);
      } catch { /* the stream below reports problems */ }
      while (!stopped) {
        try {
          setError("");
          await streamEvents("/api/status/stream", (ev, data) => {
            if (ev !== "status" || stopped) return;
            const s = JSON.parse(data) as StatusSnapshot;
            setSnap(s);
            setLive(true);
            setHist((h) => {
              const p = compact(s.sys);
              if (h.length && h[h.length - 1].t >= p.t) return h;
              const n = [...h, p];
              return n.length > MAX_POINTS ? n.slice(n.length - MAX_POINTS) : n;
            });
          }, ctl.signal);
        } catch (e) {
          if (stopped) return;
          setLive(false);
          setError(e instanceof Error ? e.message : String(e));
        }
        if (!stopped) await new Promise((r) => setTimeout(r, 3000));
      }
    })();
    return () => { stopped = true; ctl.abort(); };
  }, []);
  return { snap, hist, live, error };
}

export const fmtBytes = (n: number): string => {
  if (!isFinite(n) || n <= 0) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n >= 100 || i === 0 ? n.toFixed(0) : n.toFixed(1)} ${u[i]}`;
};
export const fmtRate = (n: number) => `${fmtBytes(n)}/s`;
export const fmtKB = (kb: number) => fmtBytes(kb * 1024);
export function fmtDur(sec: number): string {
  sec = Math.max(0, Math.round(sec));
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}
