import type { WorldToolResponse } from "./protocol.ts";

/** Thin HTTP client for the Go world API. The world owns all simulated state. */
export class WorldClient {
	private readonly baseUrl: string;
	private readonly episodeId: string;

	constructor(baseUrl: string, episodeId: string) {
		this.baseUrl = baseUrl;
		this.episodeId = episodeId;
	}

	async callTool(tool: string, args: unknown, callId: string, signal?: AbortSignal): Promise<WorldToolResponse> {
		const res = await fetch(`${this.baseUrl}/episodes/${encodeURIComponent(this.episodeId)}/tool`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ tool, args, call_id: callId }),
			signal,
		});
		if (!res.ok) {
			throw new Error(`world ${tool}: HTTP ${res.status} ${await res.text()}`);
		}
		return (await res.json()) as WorldToolResponse;
	}
}
