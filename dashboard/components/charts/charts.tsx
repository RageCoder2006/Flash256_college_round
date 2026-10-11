"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { animate } from "animejs";

const GRID = "rgba(130,160,230,0.12)";

/** Tiny inline trend line. */
export function Spark({ data, color = "#4dd8ff", h = 34, max, min = 0, fill = true }: { data: number[]; color?: string; h?: number; max?: number; min?: number; fill?: boolean }) {
  const w = 160;
  const hi = max ?? Math.max(1, ...data);
  if (data.length < 2) return <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} aria-hidden="true" />;
  const pts = data.map((v, i) => [(i / (data.length - 1)) * w, h - 2 - ((Math.min(hi, Math.max(min, v)) - min) / Math.max(1e-9, hi - min)) * (h - 4)] as const);
  const d = pts.map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(" ");
  const id = useMemo(() => `sp${Math.random().toString(36).slice(2, 8)}`, []);
  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} preserveAspectRatio="none" aria-hidden="true">
      <defs><linearGradient id={id} x1="0" x2="0" y1="0" y2="1"><stop offset="0" stopColor={color} stopOpacity="0.35" /><stop offset="1" stopColor={color} stopOpacity="0" /></linearGradient></defs>
      {fill && <path d={`${d} L${w} ${h} L0 ${h} Z`} fill={`url(#${id})`} />}
      <path d={d} fill="none" stroke={color} strokeWidth="1.6" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

export interface Series { name: string; color: string; data: number[]; dashed?: boolean }

/** Multi-series time chart with a hover read-out. x positions are the sample index; times label the axis. */
export function Area({ series, times, height = 150, yMax, unit = "", fmt }: { series: Series[]; times: number[]; height?: number; yMax?: number; unit?: string; fmt?: (v: number) => string }) {
  const W = 640, padL = 38, padR = 8, padT = 8, padB = 18, H = height;
  const n = times.length;
  const hi = yMax ?? Math.max(1, ...series.flatMap((s) => s.data)) * 1.1;
  const [hover, setHover] = useState<number | null>(null);
  const ref = useRef<SVGSVGElement>(null);
  const f = fmt ?? ((v: number) => `${v.toFixed(v < 10 ? 1 : 0)}${unit}`);
  const x = (i: number) => padL + (n < 2 ? 0 : (i / (n - 1)) * (W - padL - padR));
  const y = (v: number) => padT + (1 - Math.min(1, Math.max(0, v / hi))) * (H - padT - padB);
  const ticks = [0, 0.5, 1].map((p) => p * hi);
  const onMove = (e: React.PointerEvent) => {
    const r = ref.current?.getBoundingClientRect();
    if (!r || n < 2) return;
    const px = ((e.clientX - r.left) / r.width) * W;
    setHover(Math.min(n - 1, Math.max(0, Math.round(((px - padL) / (W - padL - padR)) * (n - 1)))));
  };
  const t = (ms: number) => new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  return (
    <div style={{ position: "relative" }}>
      <svg ref={ref} viewBox={`0 0 ${W} ${H}`} width="100%" height={H} onPointerMove={onMove} onPointerLeave={() => setHover(null)} role="img" aria-label={series.map((s) => s.name).join(", ")}>
        {ticks.map((v) => (
          <g key={v}><line x1={padL} x2={W - padR} y1={y(v)} y2={y(v)} stroke={GRID} /><text x={padL - 5} y={y(v) + 3} textAnchor="end" fill="#7686ab" fontSize="9.5" fontFamily="var(--font-jetbrains), monospace">{f(v)}</text></g>
        ))}
        {series.map((s) => {
          if (s.data.length < 2) return null;
          const d = s.data.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join(" ");
          return (
            <g key={s.name}>
              <path d={`${d} L${x(s.data.length - 1)} ${y(0)} L${x(0)} ${y(0)} Z`} fill={s.color} fillOpacity={s.dashed ? 0 : 0.1} />
              <path d={d} fill="none" stroke={s.color} strokeWidth="1.7" strokeDasharray={s.dashed ? "4 3" : undefined} />
            </g>
          );
        })}
        {n > 1 && <><text x={padL} y={H - 4} fill="#7686ab" fontSize="9.5" fontFamily="var(--font-jetbrains), monospace">{t(times[0])}</text><text x={W - padR} y={H - 4} textAnchor="end" fill="#7686ab" fontSize="9.5" fontFamily="var(--font-jetbrains), monospace">{t(times[n - 1])}</text></>}
        {hover !== null && <line x1={x(hover)} x2={x(hover)} y1={padT} y2={H - padB} stroke="#aab7d6" strokeOpacity="0.5" strokeDasharray="3 3" />}
        {hover !== null && series.map((s) => s.data[hover] !== undefined && <circle key={s.name} cx={x(hover)} cy={y(s.data[hover])} r="3" fill={s.color} />)}
      </svg>
      <div className="chart-legend">
        {series.map((s) => (
          <span key={s.name}><i style={{ background: s.color }} />{s.name}{hover !== null && s.data[hover] !== undefined ? <b> {f(s.data[hover])}</b> : s.data.length ? <b> {f(s.data[s.data.length - 1])}</b> : null}</span>
        ))}
        {hover !== null && <span className="muted">{t(times[hover])}</span>}
      </div>
    </div>
  );
}

/** Ring gauge, 0..100 by default. */
export function Ring({ value, max = 100, color = "#35e3ac", label, sub, size = 108 }: { value: number; max?: number; color?: string; label: string; sub?: string; size?: number }) {
  const r = size / 2 - 9, c = 2 * Math.PI * r;
  const frac = Math.min(1, Math.max(0, value / max));
  const ref = useRef<SVGCircleElement>(null);
  useEffect(() => {
    if (!ref.current) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) { ref.current.style.strokeDashoffset = String(c * (1 - frac)); return; }
    animate(ref.current, { strokeDashoffset: c * (1 - frac), duration: 700, ease: "outCubic" });
  }, [frac, c]);
  return (
    <div className="ring" style={{ width: size }}>
      <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size} role="img" aria-label={`${label} ${Math.round(frac * 100)} percent`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={GRID} strokeWidth="8" />
        <circle ref={ref} cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth="8" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c} transform={`rotate(-90 ${size / 2} ${size / 2})`} style={{ filter: `drop-shadow(0 0 5px ${color})` }} />
        <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central" fill="#e9effc" fontSize={size * 0.22} fontFamily="var(--font-display), sans-serif">{Math.round(frac * 100)}%</text>
      </svg>
      <div className="ring-l">{label}</div>
      {sub && <div className="ring-s">{sub}</div>}
    </div>
  );
}

/** One bar per core, coloured by load. */
export function Cores({ values }: { values: number[] }) {
  const col = (v: number) => (v > 85 ? "#ff5577" : v > 60 ? "#ffb454" : v > 30 ? "#4dd8ff" : "#35e3ac");
  return (
    <div className="cores" role="img" aria-label="Per-core CPU use">
      {values.map((v, i) => (
        <div key={i} className="core" title={`core ${i}: ${v.toFixed(0)}%`}>
          <i style={{ height: `${Math.max(3, v)}%`, background: col(v) }} />
        </div>
      ))}
    </div>
  );
}

export interface Seg { label: string; value: number; color: string }

/** Horizontal stacked bar with a legend. */
export function Stack({ segs, total, fmt }: { segs: Seg[]; total: number; fmt: (v: number) => string }) {
  return (
    <div>
      <div className="stack" role="img" aria-label={segs.map((s) => `${s.label} ${fmt(s.value)}`).join(", ")}>
        {segs.map((s) => <i key={s.label} style={{ width: `${(100 * s.value) / Math.max(1, total)}%`, background: s.color }} title={`${s.label}: ${fmt(s.value)}`} />)}
      </div>
      <div className="chart-legend">{segs.map((s) => <span key={s.label}><i style={{ background: s.color }} />{s.label} <b>{fmt(s.value)}</b></span>)}<span className="muted">of {fmt(total)}</span></div>
    </div>
  );
}

/** Tile with a number that counts up, and an optional trend. */
export function Tile({ label, value, sub, color = "#8f80ff", trend, trendMax }: { label: string; value: string | number; sub?: string; color?: string; trend?: number[]; trendMax?: number }) {
  return (
    <div className="mtile" style={{ ["--c" as string]: color }}>
      <div className="mt-l">{label}</div>
      <div className="mt-v">{value}</div>
      {sub && <div className="mt-s">{sub}</div>}
      {trend && <div className="mt-t"><Spark data={trend} color={color} max={trendMax} h={26} /></div>}
    </div>
  );
}
