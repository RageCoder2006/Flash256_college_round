import type { AssistantMessage, Message, ToolResultMessage, UserMessage } from "@earendil-works/pi-ai";
import type { Step } from "./protocol.ts";

const zeroUsage = {
	input: 0,
	output: 0,
	cacheRead: 0,
	cacheWrite: 0,
	totalTokens: 0,
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
};

export interface HistoryModel {
	api: string;
	provider: string;
	id: string;
}

export interface BuiltHistory {
	messages: Message[];
	/** provenance labels of untrusted content already in the conversation */
	untrusted: string[];
	/** user turns already consumed by the history */
	userTurns: number;
}

/**
 * Turns recorded trace steps into the conversation a model would have seen up to that point. A trailing assistant
 * message whose tool calls were not all answered is dropped, so the model is asked to make that decision again.
 */
export function buildHistory(steps: Step[], model: HistoryModel): BuiltHistory {
	const calls = new Map<string, { name: string; args: Record<string, unknown> }>();
	for (const s of steps) {
		if (s.type === "tool_call") calls.set(String(s.data.id), { name: String(s.data.name), args: (s.data.args ?? {}) as Record<string, unknown> });
	}
	const messages: Message[] = [];
	const untrusted = new Set<string>();
	let userTurns = 0;
	let t = 0;
	for (const s of steps) {
		t += 1;
		if (s.type === "user_turn") {
			userTurns++;
			const m: UserMessage = { role: "user", content: String(s.data.text ?? ""), timestamp: t };
			messages.push(m);
		} else if (s.type === "llm_response") {
			const content: AssistantMessage["content"] = [];
			if (s.data.text) content.push({ type: "text", text: String(s.data.text) });
			const tcs = (s.data.tool_calls ?? []) as { id: string; name: string }[];
			for (const c of tcs) {
				const rec = calls.get(c.id);
				content.push({ type: "toolCall", id: c.id, name: c.name, arguments: (rec?.args ?? {}) as never });
			}
			const m: AssistantMessage = {
				role: "assistant",
				content,
				api: model.api as never,
				provider: model.provider as never,
				model: model.id,
				usage: zeroUsage,
				stopReason: tcs.length ? "toolUse" : "stop",
				timestamp: t,
			};
			messages.push(m);
		} else if (s.type === "tool_result") {
			const id = String(s.data.id);
			const rec = calls.get(id);
			const m: ToolResultMessage = {
				role: "toolResult",
				toolCallId: id,
				toolName: rec?.name ?? "unknown",
				content: [{ type: "text", text: String(s.data.content ?? "") }],
				isError: Boolean(s.data.is_error),
				timestamp: t,
			} as ToolResultMessage;
			messages.push(m);
			if (s.data.source) untrusted.add(String(s.data.source));
		}
	}
	// drop a trailing assistant message with unanswered tool calls (and anything after it)
	for (let i = messages.length - 1; i >= 0; i--) {
		const m = messages[i];
		if (m.role !== "assistant") continue;
		const ids = m.content.filter((c) => c.type === "toolCall").map((c) => (c as { id: string }).id);
		if (ids.length === 0) break;
		const answered = new Set(
			messages
				.slice(i + 1)
				.filter((x) => x.role === "toolResult")
				.map((x) => (x as ToolResultMessage).toolCallId),
		);
		if (ids.every((id) => answered.has(id))) break;
		messages.length = i;
	}
	return { messages, untrusted: [...untrusted], userTurns };
}
