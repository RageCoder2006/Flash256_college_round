export const API = process.env.NEXT_PUBLIC_API ?? "http://127.0.0.1:8787";

export interface Node {
  kind: "surface" | "ingest" | "tool" | "egress" | "outcome";
  label: string;
  blocked?: boolean;
  rule?: string;
  reason?: string;
}
export interface Side {
  trace_id: string;
  success: boolean;
  strip: Node[];
}
export interface Pair {
  key: string;
  seed_id: string;
  technique: string;
  surface: string;
  operator: string;
  payload: string;
  off?: Side;
  enforce?: Side;
}
export interface TraceSummary {
  id: string;
  kind: "attack" | "benign";
  guard_mode: string;
  model: string;
  technique?: string;
  seed_id?: string;
  surface?: string;
  operator?: string;
  success: boolean;
  progress: number;
  findings: number;
  started_at: string;
  steps: number;
}
export interface Step {
  seq: number;
  type: string;
  ts: number;
  data: Record<string, unknown>;
  hash: string;
}
export interface Verdict {
  objective_id: string;
  success: boolean;
  severity: string;
  asi?: string[];
  evidence?: string;
}
export interface Finding {
  kind: string;
  severity: string;
  tool?: string;
  detail: string;
  step_seq?: number;
}
export interface TraceFull {
  trace: {
    trace_id: string;
    scenario_id: string;
    model: string;
    guard_mode: string;
    kind: string;
    attack?: { seed_id: string; technique: string; surface: string; encoding?: string; payload: string };
    user_turns: string[];
    steps: Step[];
    verdicts: Verdict[] | null;
    findings: Finding[] | null;
    success: boolean;
    progress: number;
    progress_note?: string;
    final_text: string;
    duration_ms: number;
    started_at: string;
  };
  strip: Node[];
  chain_ok: boolean;
  head: string;
}
export interface Regression {
  tasks: number;
  passed: number;
  utility: number;
  failed?: string[];
}
export interface Validation {
  baseline: { attempts: number; successes: number; asr: number; offline_simulated: boolean; model: string };
  defended: { attempts: number; successes: number; asr: number };
  replayed_exploits: number;
  blocked: number;
  blocked_pct: number;
  regression_guard_off: Regression;
  regression_guard_on: Regression;
  utility_delta: number;
  ablation?: { variant: "without" | "only"; defense: string; successes: number; attempts: number }[];
  guard_metrics?: {
    decisions: Record<string, number>;
    by_rule: Record<string, number>;
    decision_latency_us: { p50: number; p99: number; n: number };
  };
}
export interface Discovery {
  arm: string;
  technique: string;
  surface: string;
  operator: string;
  minimized_payload: string;
  reliability: number;
  runs: number;
  trace_id: string;
  found_at_attempt: number;
}
export interface HuntResult {
  attempts: number;
  executions: number;
  discoveries: Discovery[] | null;
}
export interface Summary {
  validation: Validation | null;
  campaign: unknown;
  hunt: { guard_off?: HuntResult; guard_enforce?: HuntResult } | null;
  trace_count: number;
  scenario: string;
}
export interface AuditData {
  scenario: { id: string; name: string; description: string; tools: string[] };
  findings: Finding[];
}
export interface GuardStatus {
  reachable: boolean;
  mode?: string;
  reason?: string;
}

// ---- authentication ----
// The token lives in sessionStorage (gone when the tab closes) and is sent as a bearer header.
// It is never placed in a URL.
const KEY = "avhsol.token";
export function getToken(): string {
  try {
    return sessionStorage.getItem(KEY) ?? "";
  } catch {
    return "";
  }
}
export function setToken(t: string) {
  try {
    if (t) sessionStorage.setItem(KEY, t);
    else sessionStorage.removeItem(KEY);
  } catch {
    /* storage unavailable: the user will be asked again on reload */
  }
}

export class AuthError extends Error {}

function headers(extra?: Record<string, string>): Record<string, string> {
  const t = getToken();
  return { ...(t ? { Authorization: `Bearer ${t}` } : {}), ...extra };
}

async function check(r: Response, path: string) {
  if (r.status === 401) {
    window.dispatchEvent(new Event("ab-auth-required"));
    throw new AuthError("sign in required");
  }
  if (!r.ok) throw new Error((await r.text()).trim() || `${path}: HTTP ${r.status}`);
}

export async function get<T>(path: string): Promise<T> {
  const r = await fetch(API + path, { cache: "no-store", headers: headers() });
  await check(r, path);
  return r.json() as Promise<T>;
}

export async function post<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(API + path, { method: "POST", headers: headers({ "content-type": "application/json" }), body: JSON.stringify(body) });
  await check(r, path);
  return r.json() as Promise<T>;
}

/** Reads a server-sent-event stream with fetch so the Authorization header can be sent. */
export async function streamEvents(path: string, onEvent: (event: string, data: string) => void, signal?: AbortSignal) {
  const r = await fetch(API + path, { headers: headers(), signal, cache: "no-store" });
  await check(r, path);
  const reader = r.body!.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let i: number;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const block = buf.slice(0, i);
      buf = buf.slice(i + 2);
      let ev = "message";
      let data = "";
      for (const line of block.split("\n")) {
        if (line.startsWith("event: ")) ev = line.slice(7);
        else if (line.startsWith("data: ")) data += line.slice(6);
      }
      onEvent(ev, data);
    }
  }
}

/** Make invisible Unicode visible: tag characters decode to their ASCII twin. */
export function revealHidden(text: string): { parts: { t: string; hidden: boolean }[]; hiddenCount: number } {
  const parts: { t: string; hidden: boolean }[] = [];
  let hiddenCount = 0;
  let buf = "";
  let hid = "";
  const flush = () => {
    if (buf) parts.push({ t: buf, hidden: false });
    if (hid) parts.push({ t: hid, hidden: true });
    buf = "";
    hid = "";
  };
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    const isTag = cp >= 0xe0000 && cp <= 0xe007f;
    const isOther = (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x2064) || cp === 0xfeff;
    if (isTag || isOther) {
      hiddenCount++;
      if (buf) {
        parts.push({ t: buf, hidden: false });
        buf = "";
      }
      hid += isTag ? String.fromCodePoint(cp - 0xe0000) : `⟨U+${cp.toString(16).toUpperCase()}⟩`;
    } else {
      if (hid) {
        parts.push({ t: hid, hidden: true });
        hid = "";
      }
      buf += ch;
    }
  }
  flush();
  return { parts, hiddenCount };
}

export interface Advisory {
  trace_id: string;
  title: string;
  summary: string;
  root_cause: string;
  fixes: string[] | null;
  model: string;
  error?: string;
}

// ---- trace graph ----
export interface EpisodeRow {
  id: string;
  kind: string;
  scenario: string;
  target: string;
  guard_mode: string;
  start_ms: number;
  critical_objective_achieved: boolean;
}
export interface PathStep {
  seq: number;
  type: string;
  name?: string;
  args?: string;
  content?: string;
  source?: string;
  decision?: string;
  rules?: string[];
  tainted_by?: number;
  secrets?: string[];
}
export interface Belief {
  objective: string;
  success: boolean;
  evidence: string;
  valid_from: number;
  rec_from: number;
  rec_to?: number;
}
export interface TechniqueStat {
  technique: string;
  episodes: number;
  succeeded: number;
  rate: number;
  stopped_by?: string[];
}
export interface GNode {
  id: string;
  kind: string;
  label: string;
  seq: number;
  flag?: string;
}
export interface GEdge {
  from: string;
  to: string;
  type: string;
}
export interface Subgraph {
  nodes: GNode[];
  edges: GEdge[];
}
export interface SimilarHit {
  score: number;
  kind: string;
  episode: string;
  seq: number;
  technique?: string;
  guard_mode: string;
  succeeded: boolean;
  text: string;
}
export interface GraphAnswer {
  answer: string;
  evidence: SimilarHit[];
  episodes: string[];
}

/** Downloads a generated report. It is saved as a file, never rendered inside the dashboard's own origin. */
export async function downloadReport(format: string, skeleton: string) {
  const r = await fetch(`${API}/api/report?format=${encodeURIComponent(format)}&skeleton=${encodeURIComponent(skeleton)}`, { headers: headers(), cache: "no-store" });
  await check(r, "/api/report");
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `avhsol-report.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
