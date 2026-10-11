import Link from "next/link";
import { ArchDiagram } from "@/components/ArchDiagram";
import { Connectors, ForkTimeline, IntelFlow, Isolation } from "@/components/pitch/diagrams";

export interface Slide { id: string; kicker?: string; body: React.ReactNode; notes: string }

export const SLIDES: Slide[] = [
  {
    id: "title",
    notes: "Open with the one-line promise: we attack an AI agent the way a real adversary would, prove what worked, and keep the proof. Name the team. Say that everything you are about to see is running software, and that you will be explicit about what is and is not verified.",
    body: (
      <>
        <div className="kicker rv">Autonomous red team for AI agents</div>
        <h1 className="rv">Break your agent <span className="grad">before someone else does.</span></h1>
        <p className="lead rv">AVHSOL attacks an agent through the content it reads, proves what worked with a replayable trace, shows whether a guard stops it, and keeps everything in a graph a security team can question.</p>
        <p className="lead rv" style={{ fontSize: "1rem" }}>Agentic Vulnerability Hunter with Simulated Offensive Layers · <b style={{ color: "var(--ink)" }}>David Porathur</b> and <b style={{ color: "var(--ink)" }}>Rishit Baitule</b></p>
      </>
    ),
  },
  {
    id: "problem",
    kicker: "The problem",
    notes: "Agents are useful because they read things and then act. That is also the attack surface. Walk the left card as a story: a README, an email, a web page or a tool result is untrusted text, and the agent cannot reliably tell data from instructions. The right card lists classes of incident seen in public advisories; do not quote CVE numbers from memory, point at the live Threat intel page instead.",
    body: (
      <>
        <h2 className="rv">An agent reads untrusted text, then <span className="grad">acts with real tools.</span></h2>
        <div className="cols two">
          <div className="pc hot rv"><h3>One hidden sentence is enough</h3><p>A README, an email, a web page or a tool result can carry instructions. The agent cannot reliably tell data from commands, so it may run a shell command, send a file, or call an API on the attacker&apos;s behalf, with the user&apos;s credentials.</p></div>
          <div className="pc vio rv"><h3>Classes of incident in public advisories</h3><ul><li>poisoned project files leading to credential exfiltration</li><li>repository-embedded tool configuration executing on open</li><li>a public issue leading to a private-data leak</li><li>exfiltration through rendered markdown images</li><li>an agent under evaluation reaching beyond its sandbox</li></ul></div>
        </div>
        <p className="lead rv" style={{ marginTop: 16 }}>Every one of these is reachable by someone who never touches the agent directly.</p>
      </>
    ),
  },
  {
    id: "gap",
    kicker: "Why testing falls short",
    notes: "Three failure modes of how agents are tested today. Then the bar we set ourselves: automatic, adversarial, evidence-based, repeatable, and it must measure the cost of defending, not just the benefit.",
    body: (
      <>
        <h2 className="rv">Today&apos;s testing produces opinions, <span className="grad">not evidence.</span></h2>
        <div className="cols">
          <div className="pc rv"><h3>Manual red-teaming</h3><p>Skilled, slow, and not repeatable after the next model or prompt change.</p></div>
          <div className="pc rv"><h3>Fixed prompt lists</h3><p>Attackers adapt. A static list tests yesterday&apos;s attacks and says nothing about new ones.</p></div>
          <div className="pc rv"><h3>&quot;The model says it looks safe&quot;</h3><p>A model grading itself is not a measurement. It also cannot show how data moved.</p></div>
        </div>
        <div className="cols two">
          <div className="pc cool rv"><h3>What we hold ourselves to</h3><ul><li>automatic and adaptive</li><li>success decided by the world, never by a model</li><li>replayable, signed evidence</li><li>measure the guard <i>and</i> what it costs normal work</li></ul></div>
          <div className="pc cy rv"><h3>Built for a real team</h3><p>Defence-grade handling: secrets never stored, role-based access, a tamper-evident audit log, and a report a security team can hand to a client.</p></div>
        </div>
      </>
    ),
  },
  {
    id: "what",
    kicker: "What AVHSOL is",
    notes: "Four verbs. Attack: an adaptive attacker, not a list. Prove: deterministic oracles. Defend: replay every working exploit through a Rust guard and run normal tasks both ways. Remember: a bitemporal graph you can query, correct and replay. Keep it short; the next slide shows the flow.",
    body: (
      <>
        <h2 className="rv">One platform: <span className="grad">attack, prove, defend, remember.</span></h2>
        <div className="cols" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))" }}>
          <div className="pc hot rv"><div className="big">Attack</div><p>An adaptive attacker plants hidden instructions in what the agent reads and learns from every attempt. Seeds come from public threat intelligence too.</p></div>
          <div className="pc amb rv"><div className="big">Prove</div><p>Deterministic oracles check the world: did a planted secret reach a server, was a host file read. Never the model&apos;s opinion.</p></div>
          <div className="pc cool rv"><div className="big">Defend</div><p>Every working exploit is replayed through a Rust guard. Normal tasks run with and without it, so the cost is measured.</p></div>
          <div className="pc vio rv"><div className="big">Remember</div><p>Everything lands in a bitemporal graph: query it, correct it, replay any run, fork it.</p></div>
        </div>
      </>
    ),
  },
  {
    id: "flow",
    kicker: "How a run works",
    notes: "Walk left to right. Audit is static: what the agent is allowed to do. Attack plants the payload where a legitimate task will read it. Prove is the oracle plus re-runs for reliability and shrinking the payload. Defend replays through the guard and ablates one defense at a time. Report is a signed, branded document.",
    body: (
      <>
        <h2 className="rv">From a hidden sentence to a <span className="grad">signed report.</span></h2>
        <div className="steps5">
          {[["Audit", "Static review: over-privilege, the lethal trifecta of private data + untrusted input + an exit."], ["Attack", "Plant instructions on a surface a normal task will read. The attacker mutates and learns."], ["Prove", "Oracle checks the world. Winners are re-run for reliability and shrunk to the smallest payload."], ["Defend", "Replay through the Rust guard, run benign tasks both ways, remove one defense at a time."], ["Report", "Branded report laid out by a JSON skeleton: HTML, PDF, Markdown, JSON, SARIF."]].map(([t, d], i, a) => (
            <div key={t} className="st rv"><b>{i + 1} · {t}</b><span>{d}</span>{i < a.length - 1 && <i>›</i>}</div>
          ))}
        </div>
        <p className="lead rv" style={{ marginTop: 22 }}>Nothing the model says changes the outcome. A leak counts only if a planted canary secret actually arrives.</p>
      </>
    ),
  },
  {
    id: "proof",
    kicker: "Evidence you can trust",
    notes: "This is the credibility slide. Canary secrets and a canary server make success unambiguous. Traces are hash-chained and Ed25519-signed, so a forged or re-chained trace fails verification. Secrets are replaced by fingerprints before anything is stored, so the evidence store is not itself a leak.",
    body: (
      <>
        <h2 className="rv">Success is decided by <span className="grad">the world, not the model.</span></h2>
        <div className="cols">
          <div className="pc amb rv"><h3>Deterministic oracles</h3><ul><li>canary secret reaches a canary server</li><li>host file read from inside the sandbox</li><li>forbidden tool call</li><li>no-attack control beside every result</li></ul></div>
          <div className="pc vio rv"><h3>Signed, replayable traces</h3><ul><li>every step hash-chained</li><li>Ed25519 signature over the chain head</li><li>a re-chained forgery fails verification</li><li>verify any trace with one command</li></ul></div>
          <div className="pc cool rv"><h3>Safe to store</h3><ul><li>secrets reduced to fingerprints before storage</li><li>attacker text escaped everywhere it is rendered</li><li>errored runs counted separately, never as &quot;defended&quot;</li></ul></div>
        </div>
      </>
    ),
  },
  {
    id: "arch",
    kicker: "Architecture",
    notes: "Read the diagram top to bottom. The dashboard talks to a Go control plane. Go orchestrates: campaigns, oracles, traces, graph, reports, and now the intel layer, scenario generator, live revive and connectors. TypeScript runs the agents, on a vendored fork of pi. Rust enforces: the guard proxy sees every model exchange, and the sandbox confines the agent. Confinement is Landlock by default or gVisor. Neo4j and Qdrant hold the graph and vectors. The purple box at the bottom is the local intel cache; point out that nothing is fetched during a test.",
    body: (
      <>
        <h2 className="rv" style={{ marginBottom: 6 }}>Go orchestrates. Rust enforces. <span className="grad">TypeScript runs the agents.</span></h2>
        <div className="rv"><ArchDiagram id="deck-arch" /></div>
      </>
    ),
  },
  {
    id: "intel",
    kicker: "Threat intelligence",
    notes: "This is what connects the platform to the real world. Six public sources feed a local cache. Sync is explicit and audited; nothing is fetched while a test runs, and an air-gapped site loads a signed bundle. The cache is used three ways: attack seeds written from advisories (validated, no real URLs, each keeps its advisory id), Intel nodes in the knowledge graph so answers can cite them, and context in the report. Be clear that intel never changes a risk rating and that an advisory match is not proof the target has that bug. Live demo: the Threat intel page.",
    body: (
      <>
        <h2 className="rv">Public intelligence, <span className="grad">wired into every run.</span></h2>
        <div className="rv"><IntelFlow /></div>
        <p className="lead rv" style={{ marginTop: 6, fontSize: "1rem" }}>Explicit, audited sync · offline signed bundles for air-gapped sites · third-party text is cleaned and always treated as data · intel never changes a risk rating.</p>
      </>
    ),
  },
  {
    id: "connect",
    kicker: "Test any agent",
    notes: "The goal is any agent. The simplest way in is your own code: run avhsol . in the agent's directory and it reads the code, then attacks it in the sandbox and writes the report that the dashboard shows. A CLI agent is run for real inside the sandbox with its only route to a model going through our proxy, so we see every call; the proxy speaks the OpenAI wire and the Anthropic wire. An MCP agent also gets a deliberately poisoned MCP server. An HTTP agent is a black box; we say so in the report. The scenario generator turns a tool list, or a live MCP server, into a tested scenario with lint.",
    body: (
      <>
        <h2 className="rv">Four ways in, <span className="grad">one set of oracles.</span></h2>
        <div className="rv"><Connectors /></div>
      </>
    ),
  },
  {
    id: "contain",
    kicker: "Containment",
    notes: "A tool that runs hostile agents has to contain them. The default is Landlock plus seccomp: fast, needs no root. The stronger option is gVisor: no network at all, a user-space kernel, and the two ports the agent needs are tunnelled over stdio to a host process that dials only an allow-list. We tested both with the same scripted agent and got identical oracle results. Neither is a virtual machine; a micro-VM tier is on the roadmap.",
    body: (
      <>
        <h2 className="rv">Hostile agents need <span className="grad">real containment.</span></h2>
        <div className="rv"><Isolation /></div>
      </>
    ),
  },
  {
    id: "graph",
    kicker: "Remember and explain",
    notes: "Every step, tool call, guard decision and verdict goes into Neo4j, with vectors in Qdrant. Two clocks: when it happened and when we recorded or changed our mind; corrections never overwrite. You can ask questions with GraphRAG and the answer cites evidence. The dashboard replays a run as a command centre: telemetry, an attack-chain checklist, a threat meter and a narration of each step. Live demo here: open the neural graph, click a breached run.",
    body: (
      <>
        <h2 className="rv">A graph a security team can <span className="grad">question, replay and correct.</span></h2>
        <div className="cols">
          <div className="pc vio rv"><h3>Bitemporal</h3><p>When it happened versus when we recorded or revised it. A correction closes the old belief and links the new one.</p></div>
          <div className="pc cy rv"><h3>GraphRAG + activation</h3><p>Ask in plain language. The answer cites evidence, and the parts of the 3D graph it used light up, fading with causal distance.</p></div>
          <div className="pc hot rv"><h3>Command-centre replay</h3><p>Watch a run step by step with live telemetry, an attack-chain checklist, a threat meter and a plain-language description of each command.</p></div>
          <div className="pc amb rv"><h3>Threat-intel knowledge graph</h3><p>Advisories, data sources, techniques, OWASP / ATLAS ids and packages as one explorable graph you can query.</p></div>
        </div>
      </>
    ),
  },
  {
    id: "whatif",
    kicker: "What if?",
    notes: "Two ways to ask what would have happened. The policy time machine replays recorded history through a different policy with no model calls: which past exploits it would have stopped and which legitimate tasks it would have broken. Live fork goes further: re-walk a recorded run up to a step and let the live model take over, with the guard on or a tool result edited. Each fork is one sample, never a verdict. We ran it against the real model after a live test exposed and fixed a path bug.",
    body: (
      <>
        <h2 className="rv">Replay history. <span className="grad">Fork it.</span></h2>
        <div className="rv"><ForkTimeline /></div>
        <div className="cols two">
          <div className="pc cool rv"><h3>Policy time machine</h3><p>Replay recorded runs through a new policy with no model calls: which past exploits it would have stopped, which legitimate tasks it would have broken.</p></div>
          <div className="pc vio rv"><h3>Live fork</h3><p>Re-walk a run to just before a step, then let the live model decide again with the guard on, or with a tool result edited.</p></div>
        </div>
      </>
    ),
  },
  {
    id: "report",
    kicker: "The deliverable",
    notes: "The report is what a client receives. The layout is a JSON skeleton, so a different required format is a different file, not code. It claims only what was measured: no rating for simulated runs, reliability only with at least three repeats, errored runs excluded, a no-attack control beside every result. Findings carry related public advisories and taxonomy ids, but those never alter the rating.",
    body: (
      <>
        <h2 className="rv">A branded security report that <span className="grad">only claims what was measured.</span></h2>
        <div className="cols">
          <div className="pc cy rv"><h3>JSON skeleton → any layout</h3><p>The layout is data. HTML, PDF, Markdown, JSON and SARIF from one engine; a new required format is a new file.</p></div>
          <div className="pc amb rv"><h3>Findings with context</h3><p>Attack path, timeline, payload, effect of the guard, analyst reasoning, reproduction, related public advisories and OWASP / ATLAS ids.</p></div>
          <div className="pc cool rv"><h3>Honest by construction</h3><ul><li>no rating for simulated runs</li><li>reliability needs 3+ repeats</li><li>errored runs excluded, listed</li><li>intel never changes the rating</li></ul></div>
        </div>
      </>
    ),
  },
  {
    id: "results",
    kicker: "Results so far",
    notes: "Lead with the caveat, then the numbers. One model, small samples. The first three rows are the earlier live runs. The last row matters: the newest run used intel-derived seeds against the real model and the sandboxed pi agent. None achieved a critical objective. Ten of ten hit the weaker secret-printed objective, but the no-attack control hit it three of six times because the model reads .env by itself, so that is a modest effect, not a 100 percent attack rate. Say this out loud; it is what makes the rest credible.",
    body: (
      <>
        <h2 className="rv">Real numbers, <span className="grad">with the caveats attached.</span></h2>
        <table className="res rv">
          <thead><tr><th>Setup</th><th>Result</th></tr></thead>
          <tbody>
            <tr><td>Sandboxed coding agent, guard off</td><td><span className="n">5 / 13</span> runs leaked the canary credentials; no-attack control <span className="n">0 / 6</span></td></tr>
            <tr><td>Same attacks, guard enforcing</td><td><span className="n">5 / 5</span> confirmed exfiltrations blocked; <span className="n">3 / 3</span> benign tasks still pass</td></tr>
            <tr><td>HR assistant, email exfiltration</td><td>model resisted <span className="n">0 / 12</span> fixed and <span className="n">0 / 15</span> model-written payloads</td></tr>
            <tr><td>Intel-derived seeds, real model + pi agent</td><td><span className="n">0 / 10</span> critical; <span className="n">10 / 10</span> weaker &quot;secret printed&quot; vs control <span className="n">3 / 6</span> (p = 0.036)</td></tr>
          </tbody>
        </table>
        <div className="caveat rv">One model, small samples, thinking disabled on the coding target. The model reads <code>.env</code> by itself about half the time, so &quot;secret printed&quot; is not counted as a critical exploit. Errored runs are excluded, never counted as defended.</div>
      </>
    ),
  },
  {
    id: "security",
    kicker: "Security of the platform itself",
    notes: "A security tool has to be hard to attack. Services bind loopback only; role-based tokens compared in constant time; failed-login throttling; a hash-chained audit log of every state-changing request and every sync; signed traces and bundles; hardened non-root containers; databases that reject anonymous access; secrets redacted before storage.",
    body: (
      <>
        <h2 className="rv">The tool that tests agents has to be <span className="grad">hard to attack too.</span></h2>
        <div className="cols">
          <div className="pc vio rv"><h3>Access</h3><ul><li>loopback-only services</li><li>viewer / analyst / operator / admin tokens, constant-time compare</li><li>failed-login throttling, security headers</li></ul></div>
          <div className="pc amb rv"><h3>Integrity</h3><ul><li>hash-chained audit log, including intel syncs</li><li>signed traces and signed intel bundles</li><li>secrets redacted before storage</li></ul></div>
          <div className="pc cool rv"><h3>Containment</h3><ul><li>non-root, capability-dropped containers</li><li>databases reject anonymous access</li><li>third-party text cleaned, escaped, treated as data</li></ul></div>
        </div>
      </>
    ),
  },
  {
    id: "close",
    notes: "Finish on the line, then go to the live demo: the Threat intel page, then a breached run in the neural graph. Offer the repo and the docs folder.",
    body: (
      <>
        <div className="kicker rv">Thank you</div>
        <h1 className="rv">Test the agent. <span className="grad">Keep the proof.</span></h1>
        <p className="lead rv">Open the console for the live demo: threat-intelligence graph, command-centre replay, and a signed report.</p>
        <div className="rv demo-cta">
          <Link className="btn" href="/console">Open the console</Link>
          <Link className="btn ghost" href="/console/intel">Threat intelligence</Link>
          <Link className="btn ghost" href="/console/graph">Neural graph</Link>
        </div>
        <p className="lead rv" style={{ marginTop: 26, fontSize: "1rem" }}>Made by <b style={{ color: "var(--ink)" }}>David Porathur</b> and <b style={{ color: "var(--ink)" }}>Rishit Baitule</b>. Harness forked from pi (MIT); bitemporal modelling follows utopia (Apache-2.0); detectors ported from TRIVEKTRA (GPLv3).</p>
      </>
    ),
  },
];

