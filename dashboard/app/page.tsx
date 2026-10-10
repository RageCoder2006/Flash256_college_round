"use client";
import Link from "next/link";
import { useEffect, useRef } from "react";
import { animate, stagger } from "animejs";
import { ArrowRight, Brain, Crosshair, Fingerprint, GitBranch, Lock, ScrollText, ShieldCheck, Waypoints } from "lucide-react";
import { ArchDiagram } from "@/components/ArchDiagram";
import { Logo } from "@/components/Logo";
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

const FEATURES = [
  { i: Crosshair, t: "It attacks like an adversary", d: "A pi agent driven by your own model hides instructions in the content your agent reads, then searches for the ones that work instead of replaying a fixed list." },
  { i: ShieldCheck, t: "The oracle decides, not the model", d: "A planted canary secret reaching a canary server, a host file read from the sandbox, a forbidden tool call. Deterministic checks, never an opinion." },
  { i: Fingerprint, t: "Signed, replayable evidence", d: "Every step is hash-chained and Ed25519-signed. Secrets are reduced to fingerprints before anything is stored." },
  { i: Waypoints, t: "A causal graph of the run", d: "Which untrusted read tainted which call, what the guard decided, which secret was touched. Stored in Neo4j with vectors in Qdrant." },
  { i: GitBranch, t: "A time machine for policy", d: "Replay recorded history through a different policy with no model calls: which past exploits it stops, which legitimate tasks it breaks." },
  { i: Brain, t: "Ask the graph", d: "GraphRAG over every step. The answer cites its evidence, and the parts of the 3D graph it drew on light up." },
];

const FLOW = [
  ["Audit", "A static review of what the agent is allowed to do: over-privilege and the lethal trifecta of private data, untrusted input and an exit."],
  ["Attack", "The attacker plants hidden instructions in what the agent reads and tries to make it leak a canary. It learns from every attempt."],
  ["Prove", "The oracle checks the world, not the transcript. Winners are re-run for reliability and shrunk to the smallest payload that still works."],
  ["Defend", "Every working exploit is replayed through the Rust guard. Benign tasks run both ways, and defenses are ablated one at a time."],
  ["Report", "A branded security report, laid out by a JSON skeleton, in HTML, PDF, Markdown, JSON or SARIF."],
];

export default function Landing() {
  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) return;
    animate(".hero-in", { opacity: [0, 1], translateY: [28, 0], delay: stagger(110, { start: 150 }), duration: 900, ease: "outExpo" });
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        io.unobserve(e.target);
        const el = e.target as HTMLElement;
        animate(el, { opacity: [0, 1], translateY: [24, 0], duration: 800, ease: "outQuad" });
        const kids = el.querySelectorAll(".tile, .box, .steps-flow li, tbody tr, .status div");
        if (kids.length) animate(kids, { opacity: [0, 1], translateY: [14, 0], delay: stagger(70), duration: 600, ease: "outQuad" });
      }
    }, { threshold: 0.08 });
    document.querySelectorAll(".reveal").forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, []);

  return (
    <div className="lp">
      <header className="lp-nav">
        <Link href="/" className="brand"><Logo size={26} /> AVHSOL</Link>
        <nav aria-label="Sections"><a href="#what">What it does</a><a href="#flow">How a run works</a><a href="#arch">Architecture</a><a href="#results">Results</a><a href="#status">Status</a></nav>
        <Link className="btn" href="/console">Open console <ArrowRight size={15} /></Link>
      </header>

      <section className="lp-hero">
        <Lattice />
        <div className="wrap">
          <div className="eyebrow hero-in">Autonomous red team for AI agents</div>
          <h1 className="hero-in">Break your agent <span className="grad">before someone else does.</span></h1>
          <p className="lede hero-in">AVHSOL attacks an agent the way a real adversary would, proves what worked with a replayable trace, shows whether a guard stops it, and keeps everything the agent did in a graph your security team can question.</p>
          <div className="cta hero-in">
            <Link className="btn" href="/console">Open the console <ArrowRight size={15} /></Link>
            <Link className="btn ghost" href="/console/graph">Explore the neural graph</Link>
          </div>
          <p className="by hero-in">Agentic Vulnerability Hunter with Simulated Offensive Layers · Made by David Porathur and Rishit Baitule</p>
        </div>
      </section>

      <section className="sec" id="what"><div className="wrap reveal">
        <div className="eyebrow">What it does</div>
        <h2>Evidence, not opinions.</h2>
        <p className="sub">Most agent testing ends with a model saying it looks safe. AVHSOL ends with a trace you can replay, a verdict a script produced, and a graph showing exactly how the data moved.</p>
        <div className="grid c3">
          {FEATURES.map(({ i: I, t, d }) => (<div className="tile" key={t}><div className="ico"><I size={22} /></div><h3>{t}</h3><p>{d}</p></div>))}
        </div>
      </div></section>

      <section className="sec" id="flow"><div className="wrap reveal">
        <div className="eyebrow">How a run works</div>
        <h2>From a hidden sentence to a signed report.</h2>
        <ol className="steps-flow">{FLOW.map(([t, d]) => (<li key={t}><b>{t}</b><span>{d}</span></li>))}</ol>
      </div></section>

      <section className="sec" id="arch"><div className="wrap reveal">
        <div className="eyebrow">Architecture</div>
        <h2>Go orchestrates. Rust enforces. TypeScript runs the agents.</h2>
        <p className="sub">The control plane never trusts the target: model traffic and tool calls are recorded at the Rust proxy, success is decided by oracles that look at the world, and every step lands in a signed trace and a graph.</p>
        <ArchDiagram />
      </div></section>

      <section className="sec" id="graph"><div className="wrap reveal">
        <div className="eyebrow">The graph</div>
        <h2>Two clocks. Nothing is overwritten.</h2>
        <p className="sub">The graph tracks when something happened (valid time) and when we recorded or changed our mind (record time). A correction closes the old belief and links the new one, so you can always ask what the team believed on a given day. Questions are answered with GraphRAG, and a spreading-activation pass lights up the steps, payloads, techniques and defenses the answer touched, fading with causal distance.</p>
        <div className="grid c3">
          <div className="tile"><h3>Valid time</h3><p>When the tool call or leak actually occurred.</p></div>
          <div className="tile"><h3>Record time</h3><p>When AVHSOL stored it, or revised its verdict.</p></div>
          <div className="tile"><h3>Provenance</h3><p>TAINTED_BY, EVALUATED, STOPPED and REPLAY_OF edges connect cause to effect.</p></div>
        </div>
      </div></section>

      <section className="sec" id="results"><div className="wrap reveal">
        <div className="eyebrow">Results so far</div>
        <h2>Real numbers, with the caveats attached.</h2>
        <table className="res"><thead><tr><th>Setup</th><th>Result</th></tr></thead><tbody>
          <tr><td>Sandboxed coding agent, guard off</td><td><span className="num">5 / 13</span> valid runs leaked the canary credentials; control runs <span className="num">0 / 6</span></td></tr>
          <tr><td>Same attacks, guard enforcing</td><td><span className="num">5 / 5</span> blocked; <span className="num">3 / 3</span> benign tasks still pass</td></tr>
          <tr><td>HR assistant, email exfiltration</td><td>Model resisted <span className="num">0 / 12</span> fixed and <span className="num">0 / 15</span> model-written payloads</td></tr>
        </tbody></table>
        <div className="caveat">One model, small samples, thinking disabled on the coding target. An errored run is excluded, never counted as defended. Runs against the simulated model are labelled and never rated.</div>
      </div></section>

      <section className="sec" id="security"><div className="wrap reveal">
        <div className="eyebrow">Security of the platform</div>
        <h2>The tool that tests agents has to be hard to attack too.</h2>
        <div className="grid c3">
          <div className="tile"><div className="ico"><Lock size={22} /></div><h3>Access</h3><p>Loopback-only services, role tokens compared in constant time, failed-login throttling, security headers.</p></div>
          <div className="tile"><div className="ico"><ScrollText size={22} /></div><h3>Audit</h3><p>A hash-chained log of every state-changing request. Signed traces; a re-chained forgery fails verification.</p></div>
          <div className="tile"><div className="ico"><ShieldCheck size={22} /></div><h3>Containment</h3><p>Hardened containers, databases that reject anonymous access, secrets redacted before storage.</p></div>
        </div>
      </div></section>

      <section className="sec" id="status"><div className="wrap reveal">
        <div className="eyebrow">Status</div>
        <h2>What is built, and what is next.</h2>
        <div className="status">
          <div><span className="tag done">built</span>Attack, oracle, signed traces, guard replay, benign regression, ablation, policy time machine</div>
          <div><span className="tag done">built</span>Bitemporal graph, GraphRAG, 3D neural graph with run replay, hardened API, report engine</div>
          <div><span className="tag todo">next</span>Bring-your-own-agent connectors: Anthropic wire format, MCP, plain HTTP agents</div>
          <div><span className="tag todo">next</span>Automatic scenarios for arbitrary tool lists; live fork-from-a-step revive</div>
          <div><span className="tag todo">next</span>MicroVM or gVisor sandbox for hostile agents; TLS on database ports</div>
        </div>
      </div></section>

      <footer><div className="wrap">
        <div className="big">Test the agent. Keep the proof.</div>
        <p>Made by David Porathur and Rishit Baitule. Agent harness forked from pi (MIT); bitemporal modelling follows utopia (Apache-2.0); detectors ported from TRIVEKTRA (GPLv3).</p>
        <p><Link href="/console" style={{ color: "var(--cyan)" }}>Open the console →</Link></p>
      </div></footer>
    </div>
  );
}
