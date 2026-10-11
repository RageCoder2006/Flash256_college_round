export type Coverage = "done" | "partial" | "gap";
export interface KeyFeature { name: string; state: Coverage; how: string; gap?: string }

/** The seven requirements the platform was built against, and an honest account of each. Keep in step with docs/KEY-FEATURES.md. */
export const KEY_FEATURES: KeyFeature[] = [
  { name: "Autonomous attack discovery", state: "done", how: "An adaptive hunter (bandit search, model-written payloads, re-runs, payload shrinking) plus seeds written from public threat intelligence. Not a fixed list.", gap: "Evidence so far is one model and small samples." },
  { name: "Multi-stage attack analysis", state: "partial", how: "Every run records which untrusted read tainted which later call, and the causal path is drawn in the graph, the breach line and the report.", gap: "Being extended with a memory-delayed two-stage scenario and stage labels." },
  { name: "Tool and permission auditing", state: "done", how: "Static audit (over-privilege, the lethal trifecta) and a dynamic confused-deputy audit of what each call was caused by." },
  { name: "Reproducible attack traces", state: "done", how: "Hash-chained, Ed25519-signed traces with secrets reduced to fingerprints; any run can be replayed in the graph or forked with the live model.", gap: "No model-free replay command yet." },
  { name: "Defense validation", state: "done", how: "Every working exploit is replayed through the Rust guard, defenses are ablated one at a time, and a policy can be replayed against recorded history with no model calls." },
  { name: "Security evaluation dashboard", state: "done", how: "Attack paths, severity, success rates with controls, defense effectiveness, run replay, host and sandbox status, and threat intelligence." },
  { name: "Regression testing", state: "partial", how: "A benign task suite runs with and without the guard to measure what defending costs, and policies are checked against stored exploits.", gap: "No single CI gate that replays the whole stored exploit corpus yet." },
];
