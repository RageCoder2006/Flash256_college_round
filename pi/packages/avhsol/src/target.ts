import { Agent, type AgentEvent } from "@earendil-works/pi-agent-core";
import type { AssistantMessage } from "@earendil-works/pi-ai";
import { GuardClient } from "./guard.ts";
import type { EpisodeResult, EpisodeSpec, Step, StepType } from "./protocol.ts";
import { buildLlm } from "./provider.ts";
import { type ToolDetails, buildTools } from "./tools.ts";
import { WorldClient } from "./world-client.ts";

export type StepSink = (step: Step) => void;

function assistantText(msg: AssistantMessage): string {
	return msg.content
		.filter((c) => c.type === "text")
		.map((c) => (c as { text: string }).text)
		.join("");
}

/**
 * Runs one episode: a pi Agent with the scenario's tools, driven through the scenario's user turns.
 * Every pi event is mapped to a trace Step. The guard (if any) is consulted in beforeToolCall.
 */
export async function runEpisode(spec: EpisodeSpec, onStep?: StepSink): Promise<EpisodeResult> {
	const steps: Step[] = [];
	const push = (type: StepType, data: Record<string, unknown>) => {
		const step: Step = { type, ts: Date.now(), data };
		steps.push(step);
		onStep?.(step);
	};

	const world = new WorldClient(spec.world_url, spec.episode_id);
	const guard = spec.guard && spec.guard.mode !== "off" ? new GuardClient(spec.guard) : undefined;
	const { models, model, onPayload } = buildLlm(spec.llm);
	const untrustedSources = new Set<string>();
	let turns = 0;
	let finalText = "";
	let error: string | undefined;

	const agent = new Agent({
		streamFn: models.streamSimple.bind(models),
		onPayload,
		initialState: { systemPrompt: spec.system_prompt, model, tools: buildTools(spec.tools, world) },
		beforeToolCall: async ({ toolCall, args }, signal) => {
			push("tool_call", { id: toolCall.id, name: toolCall.name, args });
			if (!guard) return undefined;
			const d = await guard.decide(
				{
					episode_id: spec.episode_id,
					tool: toolCall.name,
					args,
					untrusted_sources: [...untrustedSources],
					user_turns: spec.user_turns,
				},
				signal,
			);
			push("guard", { id: toolCall.id, mode: guard.mode, ...d });
			if (d.decision === "deny" || d.decision === "approve") {
				// "approve" = human-approval gate; with no human in the loop it is a denial.
				if (guard.mode === "enforce") {
					return { block: true, reason: `Blocked by security policy: ${d.reason ?? "denied"}` };
				}
			}
			return undefined;
		},
		afterToolCall: async ({ toolCall, result, isError }) => {
			const details = (result.details ?? {}) as ToolDetails;
			if (details.untrusted && details.source) untrustedSources.add(details.source);
			const text = result.content
				.filter((c) => c.type === "text")
				.map((c) => (c as { text: string }).text)
				.join("");
			push("tool_result", { id: toolCall.id, content: text, is_error: isError, source: details.source ?? "" });
			return undefined;
		},
	});

	agent.subscribe((event: AgentEvent) => {
		if (event.type === "message_end" && event.message.role === "assistant") {
			const m = event.message as AssistantMessage;
			const calls = m.content.filter((c) => c.type === "toolCall");
			push("llm_response", {
				text: assistantText(m),
				tool_calls: calls.map((c) => ({ id: (c as { id: string }).id, name: (c as { name: string }).name })),
				stop_reason: m.stopReason,
				input_tokens: m.usage?.input ?? 0,
				output_tokens: m.usage?.output ?? 0,
				error: m.errorMessage ?? "",
			});
			if (m.stopReason === "error" && m.errorMessage) error = m.errorMessage;
		}
		if (event.type === "turn_end") turns++;
	});

	try {
		for (const userTurn of spec.user_turns) {
			push("user_turn", { text: userTurn });
			await agent.prompt(userTurn);
			await agent.waitForIdle();
			if (spec.max_turns && turns >= spec.max_turns) break;
		}
		const last = [...agent.state.messages].reverse().find((m) => m.role === "assistant") as AssistantMessage | undefined;
		finalText = last ? assistantText(last) : "";
	} catch (e) {
		error = e instanceof Error ? e.message : String(e);
	}
	return { episode_id: spec.episode_id, steps, final_text: finalText, turns, error };
}
