"use client";
import { forwardRef, useCallback, useEffect, useImperativeHandle, useMemo, useRef } from "react";
import dynamic from "next/dynamic";
import * as THREE from "three";
import { animate } from "animejs";
import { REST, SHOW_LABEL, appearance, displayValue, linkEnds, linkStyle, nodeColor, nodeSize } from "@/lib/graph3d";
import type { Scene, SceneLink, SceneNode } from "@/lib/graph3d";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ForceGraph3D = dynamic(() => import("react-force-graph-3d"), { ssr: false }) as any;

export interface NeuralHandle {
  fit: (ms?: number) => void;
  focus: (ids: string[], ms?: number) => void;
  focusNode: (id: string, ms?: number) => void;
  reheat: () => void;
  /** chase camera for replays: look at a node from the front, keeping the board readable */
  chase: (id: string, ms?: number) => void;
  overview: (pos: { x: number; y: number; z: number }, ms?: number) => void;
}

interface Props {
  scene: Scene;
  width: number;
  height: number;
  /** id → activation level 0..1; undefined = nothing queried */
  activation?: Map<string, number>;
  /** ids visible in replay; undefined = everything */
  visible?: Set<string>;
  selected?: string | null;
  onNodeClick?: (n: SceneNode) => void;
  onNodeHover?: (n: SceneNode | null) => void;
  reduced?: boolean;
}

interface Parts {
  group: THREE.Group;
  core: THREE.Mesh;
  glow: THREE.Sprite;
  v: number; // current display value
  vis: number; // 0..1 fade for replay
  visTarget: number;
}

let glowTex: THREE.Texture | null = null;
function glowTexture() {
  if (glowTex) return glowTex;
  const c = document.createElement("canvas");
  c.width = c.height = 128;
  const g = c.getContext("2d")!;
  const grad = g.createRadialGradient(64, 64, 0, 64, 64, 64);
  grad.addColorStop(0, "rgba(255,255,255,1)");
  grad.addColorStop(0.25, "rgba(255,255,255,0.45)");
  grad.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = grad;
  g.fillRect(0, 0, 128, 128);
  glowTex = new THREE.CanvasTexture(c);
  return glowTex;
}

function labelSprite(text: string, color: string) {
  const c = document.createElement("canvas");
  const g = c.getContext("2d")!;
  const font = "600 26px 'JetBrains Mono', monospace";
  g.font = font;
  const w = Math.min(380, Math.ceil(g.measureText(text).width) + 16);
  c.width = w;
  c.height = 40;
  g.font = font;
  g.fillStyle = color;
  g.textBaseline = "middle";
  g.fillText(text.length > 28 ? text.slice(0, 27) + "…" : text, 8, 22);
  const tex = new THREE.CanvasTexture(c);
  const m = new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false });
  const s = new THREE.Sprite(m);
  s.scale.set(w / 9, 40 / 9, 1);
  s.position.set(w / 18 + 4, 0, 0);
  return s;
}

const NeuralGraph = forwardRef<NeuralHandle, Props>(function NeuralGraph(
  { scene, width, height, activation, visible, selected, onNodeClick, onNodeHover, reduced },
  ref,
) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const fg = useRef<any>(null);
  const parts = useRef(new Map<string, Parts>());
  const actRef = useRef(activation);
  const visRef = useRef(visible);
  actRef.current = activation;
  visRef.current = visible;
  const fitted = useRef(false);
  const linked = useRef(new Set<string>());
  linked.current = new Set(scene.links.flatMap((l) => linkEnds(l)));
  const driver = useRef<{ stop: () => void } | null>(null);

  const selRef = useRef(selected);
  selRef.current = selected;
  const targetOf = useCallback((id: string) => {
    const base = displayValue(actRef.current?.get(id), !!actRef.current);
    return id === selRef.current ? Math.max(base, 0.92) : base;
  }, []);

  const paint = useCallback((p: Parts, n: SceneNode) => {
    const a = appearance(p.v);
    const o = a.opacity * p.vis;
    (p.core.material as THREE.MeshBasicMaterial).opacity = o;
    p.core.scale.setScalar(a.coreScale * (0.4 + 0.6 * p.vis));
    (p.glow.material as THREE.SpriteMaterial).opacity = a.glowOpacity * p.vis;
    const s = nodeSize(n) * a.glowScale * 1.6 * (reduced ? 0.8 : 1);
    p.glow.scale.set(s, s, 1);
    p.group.visible = p.vis > 0.02;
  }, [reduced]);

  // Animate every node's display value toward its target whenever activation or replay visibility changes.
  useEffect(() => {
    driver.current?.stop();
    const starts = new Map<string, [number, number]>();
    parts.current.forEach((p, id) => {
      starts.set(id, [p.v, p.vis]);
      p.visTarget = visRef.current ? (visRef.current.has(id) ? 1 : 0) : 1;
    });
    const t = { k: 0 };
    const nodes = new Map(scene.nodes.map((n) => [n.id, n]));
    const anim = animate(t, {
      k: 1,
      duration: reduced ? 0 : 900,
      ease: "outCubic",
      onUpdate: () => {
        parts.current.forEach((p, id) => {
          const s = starts.get(id) ?? [p.v, p.vis];
          p.v = s[0] + (targetOf(id) - s[0]) * t.k;
          p.vis = s[1] + (p.visTarget - s[1]) * t.k;
          const n = nodes.get(id);
          if (n) paint(p, n);
        });
      },
      onComplete: () => {
        parts.current.forEach((p, id) => {
          p.v = targetOf(id);
          p.vis = p.visTarget;
          const n = nodes.get(id);
          if (n) paint(p, n);
        });
      },
    });
    driver.current = { stop: () => anim.pause() };
    return () => { anim.pause(); };
  }, [activation, visible, selected, scene.nodes, targetOf, paint, reduced]);

  // Slow idle rotation of the whole constellation while nothing is going on.
  useEffect(() => {
    if (reduced) return;
    let raf = 0;
    let angle = 0;
    const tick = () => {
      const g = fg.current;
      if (g && !actRef.current && !visRef.current && !selectedRef.current) {
        const cam = g.camera();
        const r = Math.hypot(cam.position.x, cam.position.z);
        angle += 0.0009;
        const base = Math.atan2(cam.position.z, cam.position.x) + 0.0009;
        void angle;
        cam.position.x = r * Math.cos(base);
        cam.position.z = r * Math.sin(base);
        cam.lookAt(g.scene().position);
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [reduced]);
  const selectedRef = useRef(selected);
  selectedRef.current = selected;

  const nodeObject = useCallback(
    (n: SceneNode) => {
      const color = nodeColor(n);
      const group = new THREE.Group();
      const core = new THREE.Mesh(
        new THREE.SphereGeometry(nodeSize(n) * 0.55, 20, 20),
        new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.9 }),
      );
      const glow = new THREE.Sprite(
        new THREE.SpriteMaterial({ map: glowTexture(), color, transparent: true, opacity: 0, depthWrite: false, blending: THREE.AdditiveBlending }),
      );
      group.add(glow, core);
      if (SHOW_LABEL.has(n.kind) && n.label) group.add(labelSprite(n.label, "#cfd9f3"));
      const p: Parts = { group, core, glow, v: targetOf(n.id), vis: 1, visTarget: 1 };
      if (visRef.current) {
        p.vis = visRef.current.has(n.id) ? 1 : 0;
        p.visTarget = p.vis;
      }
      parts.current.set(n.id, p);
      paint(p, n);
      return group;
    },
    [paint, targetOf],
  );

  const linkVisible = (l: SceneLink) => {
    if (!visible) return true;
    const [a, b] = linkEnds(l);
    return visible.has(a) && visible.has(b);
  };
  const linkLit = (l: SceneLink) => {
    if (!activation) return 0.5;
    const [a, b] = linkEnds(l);
    const x = activation.get(a);
    const y = activation.get(b);
    return x !== undefined && y !== undefined ? 0.5 + 0.5 * Math.min(x, y) : 0;
  };

  useImperativeHandle(ref, () => ({
    fit: (ms = 900) => fg.current?.zoomToFit(ms, 40, (n: SceneNode) => linked.current.has(n.id)),
    reheat: () => fg.current?.d3ReheatSimulation(),
    overview: (pos, ms = 1000) => fg.current?.cameraPosition(pos, { x: 0, y: 0, z: 0 }, ms),
    chase: (id, ms = 700) => {
      const n = scene.nodes.find((x) => x.id === id);
      const g = fg.current;
      if (!n || !g || n.x === undefined) return;
      const x = n.x, y = n.y ?? 0;
      g.cameraPosition({ x: x * 0.92, y: y * 0.4 + 8, z: 125 }, { x, y: y * 0.7, z: 0 }, ms);
    },
    focusNode: (id, ms = 1100) => {
      const n = scene.nodes.find((x) => x.id === id);
      const g = fg.current;
      if (!n || !g || n.x === undefined) return;
      const dist = 110;
      const len = Math.hypot(n.x, n.y ?? 0, n.z ?? 0) || 1;
      const k = 1 + dist / len;
      g.cameraPosition({ x: n.x * k, y: (n.y ?? 0) * k, z: (n.z ?? 0) * k }, { x: n.x, y: n.y ?? 0, z: n.z ?? 0 }, ms);
    },
    focus: (ids, ms = 1300) => {
      const g = fg.current;
      if (!g) return;
      const pts = scene.nodes.filter((n) => ids.includes(n.id) && n.x !== undefined);
      if (!pts.length) return;
      const c = pts.reduce((a, n) => ({ x: a.x + (n.x ?? 0), y: a.y + (n.y ?? 0), z: a.z + (n.z ?? 0) }), { x: 0, y: 0, z: 0 });
      c.x /= pts.length; c.y /= pts.length; c.z /= pts.length;
      const spread = Math.max(40, ...pts.map((n) => Math.hypot((n.x ?? 0) - c.x, (n.y ?? 0) - c.y, (n.z ?? 0) - c.z)));
      const dist = spread * 1.5 + 40;
      const len = Math.hypot(c.x, c.y, c.z) || 1;
      const k = 1 + dist / len;
      g.cameraPosition({ x: c.x * k, y: c.y * k, z: c.z * k }, c, ms);
    },
  }));

  // forces: a looser, rounder constellation
  useEffect(() => {
    const g = fg.current;
    if (!g) return;
    g.d3Force("charge")?.strength(-90);
    g.d3Force("link")?.distance((l: SceneLink) => (l.type === "NEXT" ? 14 : l.type === "HAS_STEP" ? 26 : 40));
  }, [scene.nodes.length]);

  const data = useMemo(() => ({ nodes: scene.nodes, links: scene.links }), [scene]);
  void REST;

  return (
    <ForceGraph3D
      ref={fg}
      width={width}
      height={height}
      graphData={data}
      backgroundColor="rgba(0,0,0,0)"
      showNavInfo={false}
      nodeThreeObject={nodeObject}
      nodeThreeObjectExtend={false}
      nodeLabel={(n: SceneNode) => `<div class="tip"><b>${esc(n.kind)}</b> ${esc(n.label)}${n.flag ? ` · ${esc(n.flag)}` : ""}</div>`}
      linkVisibility={linkVisible}
      linkColor={(l: SceneLink) => {
        const c = linkStyle(l.type).color;
        return activation && linkLit(l) === 0 ? "#1a2238" : c;
      }}
      linkOpacity={0.6}
      linkWidth={(l: SceneLink) => Math.max(0.12, linkStyle(l.type).width * 0.32 * (activation ? 0.4 + linkLit(l) * 1.6 : 1))}
      linkDirectionalParticles={(l: SceneLink) => (activation ? (linkLit(l) > 0.6 ? 4 : 0) : reduced ? 0 : linkStyle(l.type).particles)}
      linkDirectionalParticleWidth={1.3}
      linkDirectionalParticleSpeed={0.008}
      linkDirectionalParticleColor={(l: SceneLink) => linkStyle(l.type).color}
      linkDirectionalArrowLength={(l: SceneLink) => (l.type === "NEXT" || l.type === "HAS_STEP" ? 0 : 3)}
      linkDirectionalArrowRelPos={0.92}
      warmupTicks={40}
      cooldownTicks={200}
      onNodeClick={(n: SceneNode) => onNodeClick?.(n)}
      onNodeHover={(n: SceneNode | null) => onNodeHover?.(n)}
      onEngineStop={() => { if (!fitted.current && !visRef.current && !actRef.current) { fitted.current = true; fg.current?.zoomToFit(800, 40, (n: SceneNode) => linked.current.has(n.id)); } }}
    />
  );
});

function esc(s: string) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

export default NeuralGraph;
