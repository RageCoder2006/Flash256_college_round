import { Box, C, Flow, Group, Markers } from "@/components/ArchDiagram";

const Svg = ({ children, h, label }: { children: React.ReactNode; h: number; label: string }) => (
  <svg viewBox={`0 0 1100 ${h}`} role="img" aria-label={label} style={{ width: "100%", height: "auto" }}><Markers />{children}</svg>
);

/** Threat intel: sources -> local cache -> three uses. */
export function IntelFlow() {
  return (
    <Svg h={420} label="Threat intelligence flows from public sources into a local cache and is used for seeds, the graph and reports">
      <Group x={10} y={10} w={300} h={400} color={C.intel} label="PUBLIC SOURCES" />
      {[["GitHub advisories", "reviewed, pip/npm/Go/Rust/Maven"], ["NVD", "CVEs by agent keywords"], ["OSV.dev", "agent-stack package watchlist"], ["CISA KEV + EPSS", "exploited now · likely next 30 days"], ["arXiv feeds", "research leads, never findings"], ["ATLAS · OWASP LLM · ASI", "taxonomy ids, static, offline"]].map(([t, l], i) => (
        <Box key={t} x={26} y={44 + i * 56} w={268} h={46} color={C.intel} title={t} lines={[l]} small />
      ))}
      <Box x={400} y={150} w={250} h={120} color={C.go} title="Local intel cache" lines={["private directory, 973 records today", "dedupe · cursors · enrichment kept", "text cleaned of control characters", "signed offline bundles"]} />
      <Flow d="M294 210 L400 210" color={C.intel} label="sync: explicit, audited" lx={347} ly={198} />
      <Flow d="M650 190 L760 90" color={C.intel} />
      <Flow d="M650 210 L760 210" color={C.intel} />
      <Flow d="M650 230 L760 330" color={C.intel} />
      <Box x={760} y={44} w={330} h={92} color={C.rs} title="1 · Attack seeds" lines={["advisory → model adapts the technique", "validated: placeholders only, no URLs", "every seed keeps its advisory id"]} />
      <Box x={760} y={164} w={330} h={92} color={C.db} title="2 · Knowledge graph" lines={["Intel nodes → techniques → taxonomy", "GraphRAG answers can cite advisories", "episodes link back via INSPIRED_BY"]} />
      <Box x={760} y={284} w={330} h={92} color={C.ui} title="3 · Report context" lines={["findings list related advisories", "OWASP / ATLAS ids on every finding", "never changes a risk rating"]} />
      <text x={400} y={316} fill="#8fa0c8" fontFamily="var(--font-jetbrains), monospace" fontSize={11}>Nothing is fetched during a test run.</text>
    </Svg>
  );
}

/** Ways to reach an agent. */
export function Connectors() {
  return (
    <Svg h={400} label="Three ways to test an agent: command line, MCP, and HTTP, all judged by the same oracles">
      <Box x={20} y={30} w={330} h={110} color={C.ts} title="CLI agent  (Claude Code, Codex, pi, …)" lines={["runs its real command in the sandbox", "model traffic only via the guard proxy", "OpenAI or Anthropic wire"]} />
      <Box x={20} y={160} w={330} h={110} color={C.ts} title="MCP agent" lines={["same as CLI, plus a deliberately poisoned", "MCP server: result or tool description", "carries the payload"]} />
      <Box x={20} y={290} w={330} h={90} color={C.ext} title="HTTP agent  (black box)" lines={["a remote chat endpoint; we serve the poisoned", "document and watch the canary sink"]} />
      <Flow d="M350 85 L470 195" color={C.ts} />
      <Flow d="M350 215 L470 215" color={C.ts} />
      <Flow d="M350 335 L470 235" color={C.ext} />
      <Box x={470} y={150} w={260} h={130} color={C.go} title="Same oracles for all" lines={["canary secret reached the sink", "host file read from the sandbox", "forbidden tool call", "the model never decides success"]} />
      <Flow d="M730 215 L800 215" color={C.go} />
      <Box x={800} y={110} w={280} h={90} color={C.db} title="What we can see" lines={["CLI / MCP: every model exchange", "and tool call (guard replay works)"]} small />
      <Box x={800} y={225} w={280} h={90} color={C.ext} title="HTTP: replies and effects only" lines={["no guard in the path, so no replay;", "the report says it was black-box"]} small />
      <Box x={470} y={310} w={260} h={70} color={C.intel} title="Scenario generator" lines={["tool list or live MCP server → scenario"]} small />
    </Svg>
  );
}

/** Landlock vs gVisor. */
export function Isolation() {
  return (
    <Svg h={380} label="Two confinement options: Landlock on the host kernel, or gVisor with no network and tunnelled ports">
      <Group x={10} y={10} w={500} h={360} color={C.rs} label="DEFAULT · LANDLOCK + SECCOMP" />
      <Box x={30} y={50} w={460} h={70} color={C.rs} title="avhsol-sandbox" lines={["only the episode workspace is writable", "TCP only to the guard proxy and canary sink"]} />
      <Box x={30} y={140} w={460} h={70} color={C.ext} title="Host kernel" lines={["shared with the agent; syscalls filtered by seccomp", "needs no root, no namespaces, no docker"]} />
      <text x={30} y={252} fill="#aab7d6" fontFamily="var(--font-figtree), sans-serif" fontSize={13}>Fast and simple. Not a virtual machine.</text>
      <Group x={560} y={10} w={530} h={360} color={C.rs} label="STRONGER · gVISOR (docker + runsc)" />
      <Box x={580} y={50} w={490} h={70} color={C.rs} title="gVisor container: --network none" lines={["read-only root, caps dropped, pid/mem/cpu limits", "only the workspace is writable"]} />
      <Box x={580} y={140} w={490} h={70} color={C.rs} title="gVisor user-space kernel" lines={["the agent's syscalls never reach the host kernel", "a much smaller host attack surface"]} />
      <Box x={580} y={230} w={490} h={70} color={C.ts} title="Port tunnel over the container's stdio" lines={["the host dials only the allowed ports (guard, sink);", "anything else is refused. Same oracle results as Landlock."]} />
      <text x={580} y={335} fill="#aab7d6" fontFamily="var(--font-figtree), sans-serif" fontSize={13}>Verified: reaches the allowed port, no internet, no host files, /usr read-only.</text>
    </Svg>
  );
}

/** Fork timeline. */
export function ForkTimeline() {
  const xs = [60, 190, 320, 450, 580, 710, 840];
  return (
    <Svg h={300} label="A recorded run is replayed up to a chosen step and the live model takes over">
      <line x1={40} y1={110} x2={1060} y2={110} stroke="#3a4a7a" strokeWidth={2} />
      {xs.map((x, i) => (
        <g key={x}>
          <circle cx={x} cy={110} r={i < 4 ? 11 : 9} fill={i < 4 ? "#8f80ff" : "#ff5577"} fillOpacity={i < 4 ? 0.9 : 0.5} stroke={i < 4 ? "#8f80ff" : "#ff5577"} />
          <text x={x} y={146} textAnchor="middle" fill="#8fa0c8" fontFamily="var(--font-jetbrains), monospace" fontSize={11}>{["task", "read", "result", "reply", "call", "guard", "leak"][i]}</text>
        </g>
      ))}
      <text x={60} y={80} fill="#8f80ff" fontFamily="var(--font-jetbrains), monospace" fontSize={12}>RECORDED · replayed unchanged</text>
      <text x={460} y={80} fill="#ff5577" fontFamily="var(--font-jetbrains), monospace" fontSize={12}>RECORDED · what really happened</text>
      <path d="M450 110 C 450 190, 600 190, 700 190" fill="none" stroke="#35e3ac" strokeWidth={2.2} strokeDasharray="5 6" markerEnd="url(#arr-35e3ac)" />
      <rect x={705} y={168} width={340} height={46} rx={10} fill="rgba(10,18,40,0.9)" stroke="#35e3ac" strokeOpacity={0.6} />
      <text x={720} y={188} fill="#35e3ac" fontFamily="var(--font-jetbrains), monospace" fontSize={12} fontWeight={600}>FORK · live model decides again</text>
      <text x={720} y={205} fill="#aab7d6" fontFamily="var(--font-figtree), sans-serif" fontSize={11.5}>guard enforcing, or a tool result edited</text>
      <text x={60} y={260} fill="#aab7d6" fontFamily="var(--font-figtree), sans-serif" fontSize={13}>One sample of a non-deterministic model, never a verdict. The new run is linked to the original in the graph.</text>
    </Svg>
  );
}
