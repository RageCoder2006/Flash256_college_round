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
export class ApiError extends Error {
  constructor(message: string, public status: number) {
    super(message);
  }
}

function headers(extra?: Record<string, string>): Record<string, string> {
  const t = getToken();
  return { ...(t ? { Authorization: `Bearer ${t}` } : {}), ...extra };
}

async function check(r: Response, path: string) {
  if (r.status === 401) {
    window.dispatchEvent(new Event("ab-auth-required"));
    throw new AuthError("sign in required");
  }
  if (!r.ok) throw new ApiError((await r.text()).trim() || `${path}: HTTP ${r.status}`, r.status);
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
  meta?: Record<string, unknown>;
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
export interface Activation {
  id: string;
  level: number;
}
export interface GraphAnswer {
  answer: string;
  activation?: Activation[];
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

export interface Note {
  text: string;
  risk: "info" | "watch" | "danger" | "blocked";
}
export interface Narration {
  episode: string;
  source: "llm" | "rules";
  summary: string;
  steps: Record<string, Note>;
}

// ---- threat intelligence ----
export interface IntelItem {
  id: string;
  source: string;
  kind: string; // advisory | cve | paper
  title: string;
  summary: string;
  url?: string;
  published?: string;
  modified?: string;
  severity?: string;
  cvss?: number;
  epss?: number;
  kev?: boolean;
  aliases?: string[];
  affects?: string[];
  tags?: string[];
  taxon?: string[];
}
export interface IntelHit extends IntelItem {
  score?: number;
  via: "meaning" | "text";
}
export interface IntelSource {
  name: string;
  title: string;
  role: string;
  url: string;
  description: string;
  key_env?: string;
  key_set: boolean;
  items: number;
  last_sync?: string;
  error?: string;
}
export interface IntelFacets {
  total: number;
  kinds: Record<string, number>;
  severity: Record<string, number>;
  techniques: Record<string, number>;
  kev: number;
  taxonomy_version: string;
}
export interface IntelSources {
  sources: IntelSource[];
  facets: IntelFacets;
}
export interface IntelSearch {
  query: string;
  semantic: boolean;
  hits: IntelHit[];
}

export async function put<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(API + path, { method: "PUT", headers: headers({ "content-type": "application/json" }), body: JSON.stringify(body) });
  await check(r, path);
  return r.json() as Promise<T>;
}

export async function del<T>(path: string): Promise<T> {
  const r = await fetch(API + path, { method: "DELETE", headers: headers() });
  await check(r, path);
  return r.json() as Promise<T>;
}

/** Fetches a file with the token (an <a href> or <iframe src> cannot send one). */
export async function getBlob(path: string): Promise<Blob> {
  const r = await fetch(API + path, { cache: "no-store", headers: headers() });
  await check(r, path);
  return r.blob();
}

/** Saves a blob as a file through a temporary link. */
export function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

// ---- reports ----
export interface RunRow { id: string; traces: number; scenario: string; target: string; model: string; valid_runs: number; exploits: number; asr: number; rating: string; simulated: boolean; findings: number; reports: number; modified: string; error?: string }
export interface ReportMeta { id: string; run: string; format: string; skeleton: string; title?: string; classification?: string; bytes: number; sha256: string; created_at: string; created_by: string; file: string }
export interface ReportRuns { runs: RunRow[]; skeletons: string[]; formats: string[]; pdf: boolean; defaults: Settings }
export interface Settings {
  scenario: string; seeds: string; target: string; isolation: string; guard_mode: string; offline: boolean; repeats: number; budget: number;
  report_skeleton: string; report_title: string; classification: string; refresh_sec: number; intel_sync_hours: number; disabled_defenses: string[]; mcp_enabled?: boolean; mcp_tools?: string[]; updated_by?: string; updated_at?: string;
}
export interface CatalogItem { path: string; name: string; description?: string; kind?: string; sandbox?: boolean }
export interface Catalog { scenarios: CatalogItem[]; seeds: CatalogItem[]; targets: CatalogItem[] }
// The parts of the full report the page shows. Everything else in the payload is ignored.
export interface ReportData {
  title: string; scenario: string; target: string; model: string; simulated: boolean; generated_at: string;
  attack_runs: number; valid_runs: number; errored_runs: number; control_runs: number;
  headline: string; risk_rating: string; risk_basis: string; has_findings: boolean;
  doc: { report_id: string; version: string; classification: string; date: string; status: string; authors: string };
  scope: { description: string; agent_tools: string[]; surfaces: string[]; objectives: { id: string; description: string; severity: string }[]; sandboxed: boolean; target_kind: string; techniques_tried: string[] };
  techniques: { technique: string; runs?: number; wins?: number; rate?: number }[];
  objectives: { objective: string; severity: string; attack: string; control: string }[];
  findings: { id: string; title: string; severity: string; technique: string; surface: string; reliability: number; reliability_text: string; evidence: string; runs: number; successes: number; stopped_by?: string[]; guarded_replays: number; guarded_replays_still_succeeding: number; owasp_agentic: string[]; intel?: { id: string; title: string; severity?: string; kev?: boolean; url?: string; why: string }[]; taxonomy?: string[] }[];
  defense_summary?: { replayed: number; blocked: number; still_succeeding: number; benign_guard_off: string; benign_guard_on: string; text?: string };
  recommendations: { priority: number; action: string; rationale: string; evidence: string }[];
  limitations: string[];
  integrity: { traces: number; signed: number; verified: number; unsigned: number; failed_verification: number; report_digest_sha256: string };
  threat_context?: { note: string; refs: { id: string; source: string; title: string; severity?: string; kev?: boolean }[] };
}

// ---- the shared security evaluation (identical to `avhsol summary`) ----
export interface Rate { k: number; n: number; p: number; low: number; high: number }
export interface Evaluation {
  rating: string; basis: string; simulated: boolean; valid_runs: number; errored_runs: number; control_runs: number;
  exploit: Rate; severity: Record<string, number>; max_stages: number; multi_stage_findings: number;
  objectives: { objective: string; severity: string; attack: Rate; control: Rate; verdict: string; p?: number }[];
  techniques: { technique: string; rate: Rate }[];
  defense?: { replayed: number; blocked: number; still_succeeding: number; benign_guard_off: string; benign_guard_on: string; verdict: string; contribution?: { defense: string; success_without_it: Rate; matters: boolean }[] };
  does_not_show: string[];
}

export interface PlatformTool {
  name: string; title: string; description: string; effect: "read" | "writes" | "launches"; role: string; min_role: number;
  input_schema: { properties?: Record<string, { type?: string; description?: string; enum?: string[] }>; required?: string[] };
  mcp_allowed: boolean; mcp_exposed: boolean;
}
export interface ToolsResp { tools: PlatformTool[]; mcp_enabled: boolean; connect: { stdio: string; http: string } }
