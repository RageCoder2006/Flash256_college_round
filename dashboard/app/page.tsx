"use client";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { animate, stagger } from "animejs";
import { ArrowRight, StickyNote } from "lucide-react";
import { Logo } from "@/components/Logo";
import { SLIDES } from "@/components/pitch/slides";
import "./landing.css";

/** Drifting nodes and synapses behind the hero. Cheap 2D canvas; stops when off screen or for reduced motion. */
function Lattice() {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current;
    if (!c) return;
    const g = c.getContext("2d")!;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    let w = 0, h = 0, raf = 0, on = true;
    const pts = Array.from({ length: 70 }, (_, i) => ({ x: Math.random(), y: Math.random(), vx: (Math.random() - 0.5) * 0.00018, vy: (Math.random() - 0.5) * 0.00018, hot: i % 11 === 0 }));
    const size = () => { w = c.clientWidth; h = c.clientHeight; c.width = w * dpr; c.height = h * dpr; g.setTransform(dpr, 0, 0, dpr, 0, 0); };
    size();
    window.addEventListener("resize", size);
    const io = new IntersectionObserver(([e]) => { on = e.isIntersecting; });
    io.observe(c);
    let pulse = 0;
    const draw = () => {
      raf = requestAnimationFrame(draw);
      if (!on) return;
      g.clearRect(0, 0, w, h);
      pulse += 0.012;
      for (const p of pts) { if (!reduced) { p.x += p.vx * 16; p.y += p.vy * 16; } if (p.x < 0 || p.x > 1) p.vx *= -1; if (p.y < 0 || p.y > 1) p.vy *= -1; }
      for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) {
        const dx = (pts[i].x - pts[j].x) * w, dy = (pts[i].y - pts[j].y) * h, d = Math.hypot(dx, dy);
        if (d < 150) { g.strokeStyle = `rgba(120,150,255,${(1 - d / 150) * 0.28})`; g.beginPath(); g.moveTo(pts[i].x * w, pts[i].y * h); g.lineTo(pts[j].x * w, pts[j].y * h); g.stroke(); }
      }
      pts.forEach((p, i) => {
        const r = p.hot ? 3.4 + Math.sin(pulse + i) * 1.2 : 1.8;
        g.fillStyle = p.hot ? "#ff5577" : i % 3 ? "#4dd8ff" : "#8f80ff";
        g.shadowColor = g.fillStyle as string; g.shadowBlur = p.hot ? 16 : 6;
        g.beginPath(); g.arc(p.x * w, p.y * h, r, 0, 7); g.fill();
      });
      g.shadowBlur = 0;
    };
    draw();
    return () => { cancelAnimationFrame(raf); window.removeEventListener("resize", size); io.disconnect(); };
  }, []);
  return <canvas ref={ref} aria-hidden="true" />;
}


const LABEL: Record<string, string> = {
  problem: "The problem", gap: "Why testing falls short", what: "What it is", flow: "How a run works", proof: "Evidence", arch: "Architecture",
  intel: "Threat intelligence", connect: "Test any agent", contain: "Containment", graph: "Graph and replay", whatif: "Replay and fork", report: "The report",
  results: "Results", security: "Platform security", close: "Demo",
};

export default function Landing() {
  const sections = SLIDES.filter((s) => s.id !== "title");
  const [active, setActive] = useState("top");
  const [notes, setNotes] = useState(false);
  const bar = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!reduced) animate(".hero-in", { opacity: [0, 1], translateY: [28, 0], delay: stagger(110, { start: 150 }), duration: 900, ease: "outExpo" });
    // each section animates in once, the first time it is mostly on screen, and becomes the "current" one for the dots and notes
    const seen = new WeakSet<Element>();
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        const el = e.target as HTMLElement;
        setActive(el.id);
        if (seen.has(el) || reduced) continue;
        seen.add(el);
        const rv = el.querySelectorAll(".rv");
        if (rv.length) animate(rv, { opacity: [0, 1], translateY: [26, 0], delay: stagger(95, { start: 60 }), duration: 750, ease: "outExpo" });
      }
    }, { threshold: 0.35 });
    document.querySelectorAll(".ps, .lp-hero").forEach((el) => io.observe(el));
    const onScroll = () => {
      const h = document.documentElement;
      if (bar.current) bar.current.style.width = `${(h.scrollTop / Math.max(1, h.scrollHeight - h.clientHeight)) * 100}%`;
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    const key = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const ids = ["top", ...sections.map((s) => s.id)];
      const idx = ids.indexOf(document.querySelector<HTMLElement>(".ps.cur, .lp-hero.cur")?.id ?? "top");
      if (e.key.toLowerCase() === "n") setNotes((v) => !v);
      else if (e.key === "ArrowDown" || e.key === "PageDown") { e.preventDefault(); document.getElementById(ids[Math.min(ids.length - 1, idx + 1)])?.scrollIntoView({ behavior: "smooth" }); }
      else if (e.key === "ArrowUp" || e.key === "PageUp") { e.preventDefault(); document.getElementById(ids[Math.max(0, idx - 1)])?.scrollIntoView({ behavior: "smooth" }); }
    };
    window.addEventListener("keydown", key);
    return () => { io.disconnect(); window.removeEventListener("scroll", onScroll); window.removeEventListener("keydown", key); };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    document.querySelectorAll(".ps, .lp-hero").forEach((el) => el.classList.toggle("cur", el.id === active));
  }, [active]);

  const curNotes = sections.find((s) => s.id === active)?.notes ?? "Open with the promise: attack an agent the way a real adversary would, prove what worked, keep the proof. Then scroll: the problem, the platform, the architecture, threat intelligence, results with caveats, and finish in the live demo.";

  return (
    <div className="lp">
      <div className="progress" ref={bar} aria-hidden="true" />
      <header className="lp-nav">
        <Link href="/" className="brand"><Logo size={26} /> AVHSOL</Link>
        <nav aria-label="Sections"><a href="#what">What it is</a><a href="#arch">Architecture</a><a href="#intel">Threat intel</a><a href="#results">Results</a><a href="#close">Demo</a></nav>
        <Link className="btn" href="/console">Open console <ArrowRight size={15} /></Link>
      </header>

      <nav className="snav" aria-label="Page sections">
        <a href="#top" className={active === "top" ? "on" : ""} aria-label="Top"><span>Start</span></a>
        {sections.map((s) => <a key={s.id} href={`#${s.id}`} className={active === s.id ? "on" : ""} aria-label={LABEL[s.id] ?? s.id}><span>{LABEL[s.id] ?? s.id}</span></a>)}
      </nav>

      <section className="lp-hero" id="top">
        <Lattice />
        <div className="wrap">
          <div className="eyebrow hero-in">Autonomous red team for AI agents</div>
          <h1 className="hero-in">Break your agent <span className="grad">before someone else does.</span></h1>
          <p className="lede hero-in">AVHSOL attacks an agent through the content it reads, proves what worked with a replayable trace, shows whether a guard stops it, and keeps everything in a graph your security team can question.</p>
          <div className="cta hero-in">
            <Link className="btn" href="/console">Open the console <ArrowRight size={15} /></Link>
            <Link className="btn ghost" href="/console/intel">Threat intelligence</Link>
            <Link className="btn ghost" href="/console/graph">Neural graph</Link>
          </div>
          <p className="by hero-in">Agentic Vulnerability Hunter with Simulated Offensive Layers · Made by David Porathur and Rishit Baitule</p>
          <div className="hero-scroll hero-in">Scroll ↓  or use the arrow keys</div>
        </div>
      </section>

      {sections.map((s) => (
        <section key={s.id} id={s.id} className="ps" aria-label={LABEL[s.id] ?? s.id}>
          <div className="slide-in">
            {s.kicker && <div className="kicker rv">{s.kicker}</div>}
            {s.body}
          </div>
        </section>
      ))}

      <footer><div className="wrap">
        <div className="big">Test the agent. Keep the proof.</div>
        <p>Made by David Porathur and Rishit Baitule. Agent harness forked from pi (MIT); bitemporal modelling follows utopia (Apache-2.0); detectors ported from TRIVEKTRA (GPLv3).</p>
        <p><Link href="/console" style={{ color: "var(--cyan)" }}>Open the console →</Link></p>
      </div></footer>

      <button className="notes-fab" onClick={() => setNotes((v) => !v)} aria-pressed={notes}><StickyNote size={14} /> Speaker notes (N)</button>
      {notes && <div className="notes-box" role="note"><b>Talking points</b>{curNotes}</div>}
    </div>
  );
}
