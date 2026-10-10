import { describe, expect, it } from "vitest";
import { craftPayload } from "../src/attacker.ts";
import type { CraftRequest } from "../src/protocol.ts";

const base: Omit<CraftRequest, "llm"> = {
	objective: "exfiltrate records",
	surface_kind: "document",
	target_tools: ["read_document", "send_email"],
	technique: "authority_impersonation",
	operator: "llm_rewrite",
	seed_text: "seed",
	attacker_email: "a@evil.example",
	history: [{ payload: "old", progress: 2, note: "deviated", guard_blocks: ["D4"] }],
};

describe("craftPayload", () => {
	it("returns the payload submitted through the tool", async () => {
		const r = await craftPayload({
			...base,
			llm: { kind: "scripted", scripted: [{ tool_calls: [{ name: "submit_payload", args: { payload: "NEW PAYLOAD", rationale: "r" } }] }, { text: "done" }] },
		});
		expect(r.error).toBeUndefined();
		expect(r.payload).toBe("NEW PAYLOAD");
	});

	it("reports an error instead of throwing when the model never submits", async () => {
		const r = await craftPayload({ ...base, llm: { kind: "scripted", scripted: [{ text: "I cannot help with that" }] } });
		expect(r.payload).toBe("");
		expect(r.error).toContain("no tool call");
	});
});
