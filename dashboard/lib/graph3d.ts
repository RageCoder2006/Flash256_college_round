import type { GEdge, GNode, PathStep, Subgraph } from "./api";

/** A node in the 3D scene. react-force-graph mutates these (adds x, y, z, vx...). */
export interface SceneNode {
  id: string;
  kind: string; // episode technique payload resource tool secret defense | user_turn tool_call tool_result guard
  label: string;
  flag?: string;
  seq?: number;
  ep?: string; // owning episode id (steps)
  meta?: Record<string, unknown>;
  // fixed positions used by the run replay
  fx?: number;
  fy?: number;
  fz?: number;
  x?: number;
  y?: number;
  z?: number;
}

export interface SceneLink {
  source: string | SceneNode;
  target: string | SceneNode;
  type: string;
}

export interface Scene {
  nodes: SceneNode[];
  links: SceneLink[];
}

export const emptyScene = (): Scene => ({ nodes: [], links: [] });

// ---- visual language ----

export const COLORS = {
  breach: "#ff5577",
  held: "#35e3ac",
  violet: "#8f80ff",
  cyan: "#4dd8ff",
  amber: "#ffb454",
  gold: "#ffd447",
  blue: "#5b8cff",
  steel: "#8a9cc4",
  teal: "#3fd0c9",
  ink: "#e9effc",
};

export function nodeColor(n: SceneNode): string {
  switch (n.kind) {
    case "episode": {
      const m = n.meta ?? {};
      if (m.episode_kind === "benign") return COLORS.blue;
      return m.achieved ? COLORS.breach : COLORS.held;
    }
    case "technique": return COLORS.violet;
    case "payload": return COLORS.amber;
    case "resource": return COLORS.steel;
    case "tool": return COLORS.teal;
    case "secret": return COLORS.gold;
    case "defense": return COLORS.cyan;
    case "intel": {
      if (n.flag === "kev") return COLORS.breach;
      const m = n.meta ?? {};
      if (m.item_kind === "paper") return COLORS.teal;
      return { critical: "#ff7a45", high: COLORS.amber, medium: COLORS.gold, low: COLORS.steel }[String(m.severity ?? "")] ?? COLORS.blue;
    }
    case "source": return COLORS.cyan;
    case "taxon": return "#c9a8ff";
    case "package": return COLORS.steel;
    case "user_turn": return "#aebce0";
    case "tool_call": return n.flag === "leak" ? COLORS.amber : COLORS.blue;
    case "tool_result": return n.flag === "untrusted" ? COLORS.breach : COLORS.cyan;
    case "guard": return n.flag === "blocked" ? COLORS.cyan : "#3a7d6b";
    default: return COLORS.steel;
  }
}

/** Relative size of a node's core. */
export function nodeSize(n: SceneNode): number {
  switch (n.kind) {
    case "episode": return 7;
    case "source": return 7.5;
    case "taxon": return 5;
    case "package": return 3.6;
    case "intel": return n.flag === "kev" ? 4.6 : 3.4;
    case "technique": return 6;
    case "defense": return 5.5;
    case "secret": return 5;
    case "payload": return 4.5;
    case "tool": case "resource": return 4;
    case "guard": return n.flag === "blocked" ? 4.6 : 2.6;
    default: return 3.2;
  }
}

export const SHOW_LABEL = new Set(["episode", "technique", "defense", "secret", "source", "taxon"]);

export function linkStyle(type: string): { color: string; width: number; particles: number } {
  switch (type) {
    case "TAINTED_BY": return { color: COLORS.breach, width: 1.4, particles: 2 };
    case "EVALUATED": return { color: COLORS.held, width: 1.1, particles: 1 };
    case "LEAKED": case "EXPOSED": case "TOUCHED": return { color: COLORS.amber, width: 1.2, particles: 2 };
    case "STOPPED": return { color: COLORS.cyan, width: 1.4, particles: 2 };
    case "REPLAY_OF": return { color: COLORS.violet, width: 1.1, particles: 1 };
    case "PLANTED": case "PLANTED_IN": return { color: COLORS.amber, width: 0.9, particles: 0 };
    case "INSTANCE_OF": return { color: COLORS.violet, width: 0.9, particles: 0 };
    case "RETURNED": return { color: COLORS.cyan, width: 0.7, particles: 0 };
    case "MOTIVATES": return { color: COLORS.violet, width: 0.9, particles: 1 };
    case "MAPS_TO": return { color: "#c9a8ff", width: 0.9, particles: 0 };
    case "AFFECTS": return { color: COLORS.steel, width: 0.7, particles: 0 };
    case "FROM_SOURCE": return { color: COLORS.cyan, width: 0.5, particles: 0 };
    case "ALIAS_OF": return { color: COLORS.gold, width: 1.1, particles: 2 };
    case "INSPIRED_BY": return { color: COLORS.amber, width: 1.1, particles: 1 };
    case "NEXT": return { color: "#6f84b8", width: 0.5, particles: 0 };
    case "HAS_STEP": return { color: "#6f84b8", width: 0.4, particles: 0 };
    default: return { color: "#6f84b8", width: 0.6, particles: 0 };
  }
}

// ---- building the scene from API data ----

const KIND: Record<string, string> = { step: "step" };

export function fromOverview(g: Subgraph): Scene {
  const nodes: SceneNode[] = g.nodes.map((n) => ({ id: n.id, kind: n.kind, label: n.label, flag: n.flag, meta: n.meta as Record<string, unknown> | undefined }));
  const links: SceneLink[] = g.edges.map((e) => ({ source: e.from, target: e.to, type: e.type }));
  return { nodes, links };
}

export function epOfStep(id: string): string | undefined {
  const i = id.indexOf("#");
  return i > 0 ? id.slice(0, i) : undefined;
}

/**
 * Adds an episode's steps (and the artifacts they touch) to the scene without disturbing nodes that
 * are already there, so the layout does not jump. Returns a new Scene that reuses existing node objects.
 */
export function mergeEpisode(scene: Scene, episode: string, sub: Subgraph): Scene {
  const have = new Map(scene.nodes.map((n) => [n.id, n]));
  const nodes = [...scene.nodes];
  const linkKey = new Set(scene.links.map((l) => keyOf(l)));
  const links = [...scene.links];
  const steps: SceneNode[] = [];
  for (const n of sub.nodes as GNode[]) {
    if (have.has(n.id)) continue;
    const node: SceneNode = { id: n.id, kind: n.kind, label: n.label, flag: n.flag, seq: n.seq, ep: epOfStep(n.id) };
    have.set(n.id, node);
    nodes.push(node);
    if (n.id.includes("#")) steps.push(node);
  }
  const add = (a: string, b: string, t: string) => {
    const l: SceneLink = { source: a, target: b, type: t };
    const k = keyOf(l);
    if (!linkKey.has(k) && have.has(a) && have.has(b)) {
      linkKey.add(k);
      links.push(l);
    }
  };
  for (const e of sub.edges as GEdge[]) add(e.from, e.to, e.type);
  const first = steps.sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0))[0];
  if (first && have.has("ep:" + episode)) add("ep:" + episode, first.id, "HAS_STEP");
  return { nodes, links };
}

export function keyOf(l: SceneLink): string {
  const s = typeof l.source === "string" ? l.source : l.source.id;
  const t = typeof l.target === "string" ? l.target : l.target.id;
  return `${s}>${t}:${l.type}`;
}

export function linkEnds(l: SceneLink): [string, string] {
  return [typeof l.source === "string" ? l.source : l.source.id, typeof l.target === "string" ? l.target : l.target.id];
}

// ---- run replay: steps laid out as lanes on a timeline ----

const LANE_Y: Record<string, number> = { tool_result: 26, user_turn: 0, tool_call: 0, guard: -26 };
const ART_Y: Record<string, number> = { technique: 92, resource: 60, tool: 60, secret: -62, payload: -62, defense: -54 };
export const STEP_SPACING = 17;

/**
 * Fixes a run to a readable board: steps on lanes along a timeline (results above, calls in the middle, guard
 * below), the episode at the left end, and the artifacts it touched above or below the step that touched them.
 */
export function layoutRun(scene: Scene, episode: string): SceneNode[] {
  const steps = scene.nodes.filter((n) => n.ep === episode && n.seq !== undefined).sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
  steps.forEach((n, i) => {
    n.fx = (i - (steps.length - 1) / 2) * STEP_SPACING;
    n.fy = LANE_Y[n.kind] ?? 0;
    n.fz = (i % 2 ? 6 : -6) + (n.kind === "guard" ? 8 : 0);
  });
  const minX = steps.length ? (steps[0].fx ?? 0) : 0;
  const stepIds = new Set(steps.map((s) => s.id));
  const byId = new Map(scene.nodes.map((n) => [n.id, n]));
  const run = runNodeIds(scene, episode);
  const taken = new Map<string, number>();
  for (const id of run) {
    const n = byId.get(id);
    if (!n || stepIds.has(id)) continue;
    if (n.kind === "episode") {
      n.fx = minX - 46; n.fy = 0; n.fz = 0;
      continue;
    }
    const xs: number[] = [];
    for (const l of scene.links) {
      const [x, y] = linkEnds(l);
      const other = x === id ? y : y === id ? x : "";
      if (other && stepIds.has(other)) xs.push(byId.get(other)?.fx ?? 0);
    }
    let x = xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : minX;
    const key = `${n.kind}:${Math.round(x / 8)}`;
    const k = taken.get(key) ?? 0;
    taken.set(key, k + 1);
    x += k * 9;
    n.fx = x;
    n.fy = (ART_Y[n.kind] ?? 60) + (k % 2 ? 8 : 0);
    n.fz = -24;
  }
  return steps;
}

export function releaseRun(scene: Scene, episode?: string) {
  const ids = episode ? runNodeIds(scene, episode) : null;
  for (const n of scene.nodes) {
    if (!ids || ids.has(n.id)) n.fx = n.fy = n.fz = undefined;
  }
}

/** Camera position that frames a whole run from the front. */
export function runOverview(n: number) {
  const width = Math.max(1, n - 1) * STEP_SPACING + 120;
  return { x: 0, y: 6, z: Math.max(190, width * 0.62) };
}

/**
 * The nodes that belong to one run: the episode, its steps, and the payload, resources, secrets, tools and defenses
 * directly attached to them, plus the technique of that payload. Expansion is one hop from the run only, so shared
 * hubs (a technique used by many runs) never drag other runs' nodes in.
 */
export function runNodeIds(scene: Scene, episode: string): Set<string> {
  const seed = new Set<string>(["ep:" + episode]);
  for (const n of scene.nodes) if (n.ep === episode) seed.add(n.id);
  const ids = new Set(seed);
  const kinds = new Map(scene.nodes.map((n) => [n.id, n.kind]));
  const payloads = new Set<string>();
  for (const l of scene.links) {
    const [a, b] = linkEnds(l);
    if (!seed.has(a) && !seed.has(b)) continue;
    const other = seed.has(a) ? b : a;
    const k = kinds.get(other);
    if (k && ["payload", "resource", "secret", "tool", "defense"].includes(k)) {
      ids.add(other);
      if (k === "payload") payloads.add(other);
    }
  }
  for (const l of scene.links) {
    const [a, b] = linkEnds(l);
    if (l.type === "INSTANCE_OF" && payloads.has(a)) ids.add(b);
  }
  return ids;
}

// ---- activation: how bright each node looks ----

export const REST = 0.5; // display value of a node when nothing is being queried

/** Display value: 0.5 = resting, below = dimmed, above = glowing. Activated nodes map level 0..1 to 0.5..1. */
export function displayValue(level: number | undefined, active: boolean): number {
  if (!active) return REST;
  if (level === undefined) return 0.04;
  return REST + REST * Math.min(1, Math.max(0, level));
}

export function appearance(v: number) {
  const clamp = (x: number) => Math.min(1, Math.max(0, x));
  const glow = clamp((v - REST) / REST);
  return {
    opacity: 0.07 + 0.93 * clamp(v / REST),
    glow,
    glowScale: 1.5 + glow * 8.5,
    glowOpacity: glow * 0.95,
    coreScale: 1 + glow * 0.9,
  };
}

/** Plain-text description of a step for tooltips and the replay narration. */
export function describeStep(p: PathStep | undefined, n: SceneNode): string {
  if (!p) return n.label;
  switch (p.type) {
    case "user_turn": return `Task: ${p.content ?? ""}`;
    case "tool_call": return `${p.name ?? "call"} ${p.args ?? ""}${p.tainted_by !== undefined ? `  (after untrusted read #${p.tainted_by})` : ""}`;
    case "tool_result": return `${p.source ? `Untrusted content (${p.source}): ` : "Result: "}${p.content ?? ""}`;
    case "guard": return `Guard ${(p.decision ?? "").toUpperCase()} ${p.rules?.join("+") ?? ""}: ${p.content ?? ""}`;
    default: return n.label;
  }
}

void KIND;
