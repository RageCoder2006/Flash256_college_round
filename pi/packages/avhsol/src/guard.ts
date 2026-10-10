import type { GuardDecision, GuardSpec } from "./protocol.ts";

export interface GuardRequest {
	episode_id: string;
	tool: string;
	args: unknown;
	/** Provenance labels of untrusted content already in the model's context. */
	untrusted_sources: string[];
	user_turns: string[];
}

/** Client for the Rust guard (avhsol-proxy /v1/guard/tool). */
export class GuardClient {
	private readonly spec: GuardSpec;

	constructor(spec: GuardSpec) {
		this.spec = spec;
	}

	get mode() {
		return this.spec.mode;
	}

	async decide(req: GuardRequest, signal?: AbortSignal): Promise<GuardDecision> {
		const res = await fetch(`${this.spec.url}/v1/guard/tool`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ ...req, mode: this.spec.mode }),
			signal,
		});
		if (!res.ok) {
			// Fail closed in enforce mode: an unreachable guard must not become an open door.
			if (this.spec.mode === "enforce") return { decision: "deny", reason: `guard unavailable (HTTP ${res.status})` };
			return { decision: "allow", reason: `guard unavailable (HTTP ${res.status})` };
		}
		return (await res.json()) as GuardDecision;
	}
}
