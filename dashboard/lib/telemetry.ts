import type { PathStep } from "./api";

export interface Telemetry {
  steps: number;
  calls: number;
  untrusted: number;
  tainted: number;
  allowed: number;
  denied: number;
  secrets: number;
  tools: string[];
  threat: number; // 0..100
  chain: { key: string; label: string; hit: boolean }[];
}

const EGRESS = /(curl|wget|http|post|send|email|upload|nc |scp|fetch)/i;

/** Everything the command-centre readouts show, computed from the steps revealed so far. */
export function telemetry(path: PathStep[], upto: number, achieved: boolean): Telemetry {
  const seen = path.filter((p) => p.seq <= upto);
  const calls = seen.filter((p) => p.type === "tool_call");
  const untrusted = seen.filter((p) => p.type === "tool_result" && p.source).length;
  const tainted = calls.filter((p) => p.tainted_by !== undefined && p.tainted_by !== null).length;
  const guard = seen.filter((p) => p.type === "guard");
  const denied = guard.filter((p) => p.decision && p.decision !== "allow").length;
  const secrets = new Set(seen.flatMap((p) => p.secrets ?? [])).size;
  const egress = calls.some((p) => EGRESS.test(`${p.name ?? ""} ${p.args ?? ""}`));
  const chain = [
    { key: "task", label: "Task", hit: seen.some((p) => p.type === "user_turn") },
    { key: "read", label: "Untrusted read", hit: untrusted > 0 },
    { key: "taint", label: "Steered", hit: tainted > 0 },
    { key: "secret", label: "Secret touched", hit: secrets > 0 },
    { key: "egress", label: "Exit attempt", hit: egress && (tainted > 0 || secrets > 0) },
    { key: "guard", label: "Guard stopped it", hit: denied > 0 },
    { key: "breach", label: "Objective reached", hit: achieved && upto >= (path[path.length - 1]?.seq ?? 0) },
  ];
  const threat = Math.min(100, untrusted * 10 + tainted * 22 + secrets * 28 + (chain[4].hit ? 20 : 0) - denied * 8);
  return {
    steps: seen.length,
    calls: calls.length,
    untrusted,
    tainted,
    allowed: guard.length - denied,
    denied,
    secrets,
    tools: [...new Set(calls.map((p) => p.name ?? "").filter(Boolean))],
    threat: Math.max(0, threat),
    chain,
  };
}
