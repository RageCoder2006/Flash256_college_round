// Wire types shared with the Go control plane (core/internal/harness).
// Newline-delimited JSON over stdio. Keep field names in sync with Go.

export type GuardMode = "off" | "monitor" | "enforce";

export interface ScriptedToolCall {
	name: string;
	args: Record<string, unknown>;
}

/** One scripted assistant turn; used for offline/deterministic runs and cassette replay. */
export interface ScriptedTurn {
	text?: string;
	tool_calls?: ScriptedToolCall[];
}

export interface LlmSpec {
	kind: "openai" | "scripted";
	base_url?: string;
	model?: string;
	api_key?: string;
	scripted?: ScriptedTurn[];
	/** "off" disables the model's chain-of-thought via chat_template_kwargs (reasoning models can otherwise burn the whole token budget). */
	thinking?: "default" | "off";
	max_tokens?: number;
}

export interface GuardSpec {
	url: string;
	mode: GuardMode;
}

export interface EpisodeSpec {
	episode_id: string;
	world_url: string;
	llm: LlmSpec;
	system_prompt: string;
	tools: string[];
	user_turns: string[];
	max_turns?: number;
	guard?: GuardSpec;
	/**
	 * Recorded steps to start from instead of an empty conversation (live revive). They must end at a boundary: a
	 * user turn or a tool result, with every tool call answered. The model is asked to continue from there, and only
	 * the steps it produces from then on are returned.
	 */
	history?: Step[];
	/** All the user's turns for the whole conversation, for the guard's provenance check; `user_turns` are the ones still to send. */
	all_user_turns?: string[];
}

export type StepType = "user_turn" | "llm_response" | "tool_call" | "tool_result" | "guard";

export interface Step {
	type: StepType;
	ts: number;
	data: Record<string, unknown>;
}

export interface EpisodeResult {
	episode_id: string;
	steps: Step[];
	final_text: string;
	turns: number;
	error?: string;
}

export interface RpcRequest {
	id: number;
	method: string;
	params: unknown;
}

export interface RpcResponse {
	id: number;
	result?: unknown;
	error?: string;
}

/** Unsolicited progress line: {"event":"step", ...}. */
export interface RpcEvent {
	event: "step";
	episode_id: string;
	step: Step;
}

export interface WorldToolResponse {
	content: string;
	is_error: boolean;
	/** Provenance label of the content returned, e.g. "retrieved:resume_mallory". Empty if trusted. */
	source?: string;
	untrusted?: boolean;
}

export interface GuardDecision {
	decision: "allow" | "deny" | "approve";
	reason?: string;
	rule_ids?: string[];
}

export interface CraftRequest {
	llm: LlmSpec;
	objective: string;
	surface_kind: string;
	/** What the agent can do (tool names + one-line descriptions), from black-box recon. */
	target_tools: string[];
	technique: string;
	operator: string;
	seed_text: string;
	attacker_email: string;
	/** Previous attempts, newest last. */
	history: { payload: string; progress: number; note: string; guard_blocks: string[] }[];
}

export interface CraftResult {
	payload: string;
	rationale: string;
	error?: string;
}
