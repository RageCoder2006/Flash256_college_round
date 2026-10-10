import {
	type Model,
	type Models,
	createModels,
	createProvider,
	fauxAssistantMessage,
	fauxProvider,
	fauxText,
	fauxToolCall,
} from "@earendil-works/pi-ai";
import { openAICompletionsApi } from "@earendil-works/pi-ai/api/openai-completions.lazy";
import type { LlmSpec } from "./protocol.ts";

export interface BuiltLlm {
	models: Models;
	model: Model<string>;
}

/**
 * Builds the pi model stack for an episode.
 * - "openai": any OpenAI-compatible /v1 endpoint (Unsloth, llama.cpp, vLLM, or the Rust guard proxy in front of them).
 * - "scripted": deterministic replies via pi's faux provider (offline tests, cassette replay).
 */
export function buildLlm(spec: LlmSpec): BuiltLlm {
	const models = createModels();
	if (spec.kind === "scripted") {
		const faux = fauxProvider({ models: [{ id: "scripted" }] });
		let n = 0;
		faux.setResponses(
			(spec.scripted ?? []).map((turn) => {
				const blocks = [];
				if (turn.text) blocks.push(fauxText(turn.text));
				for (const tc of turn.tool_calls ?? []) {
					blocks.push(fauxToolCall(tc.name, tc.args as never, { id: `scripted_${n++}` }));
				}
				return fauxAssistantMessage(blocks.length ? blocks : "", {
					stopReason: turn.tool_calls?.length ? "toolUse" : "stop",
				});
			}),
		);
		models.setProvider(faux.provider);
		return { models, model: faux.getModel() };
	}

	const baseUrl = spec.base_url;
	const modelId = spec.model;
	if (!baseUrl || !modelId) throw new Error("llm.kind=openai requires base_url and model");
	const providerId = "agentbreak-llm";
	const apiKey = spec.api_key ?? "";
	const model: Model<"openai-completions"> = {
		id: modelId,
		name: modelId,
		api: "openai-completions",
		provider: providerId,
		baseUrl,
		reasoning: false,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 32768,
		maxTokens: 4096,
	};
	const provider = createProvider({
		id: providerId,
		name: "AgentBreak LLM",
		baseUrl,
		auth: { apiKey: { name: "llm", resolve: async () => ({ auth: apiKey ? { apiKey } : {} }) } },
		models: [model],
		api: openAICompletionsApi(),
	});
	models.setProvider(provider);
	return { models, model };
}
