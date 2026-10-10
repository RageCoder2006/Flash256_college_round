import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import type { WorldClient } from "./world-client.ts";

export interface ToolDetails {
	source?: string;
	untrusted?: boolean;
}

interface ToolDef {
	label: string;
	description: string;
	parameters: ReturnType<typeof Type.Object>;
}

/** Tool catalog. The Go world implements the behaviour; scenarios choose which names to expose. */
export const TOOL_CATALOG: Record<string, ToolDef> = {
	list_documents: {
		label: "List documents",
		description: "List the ids of all documents available in the document store.",
		parameters: Type.Object({}),
	},
	read_document: {
		label: "Read document",
		description: "Read the full text of a document by its id.",
		parameters: Type.Object({ doc_id: Type.String({ description: "Document id, e.g. resume_alice" }) }),
	},
	search_records: {
		label: "Search records",
		description: "Search employee/HR records. Returns matching records as text.",
		parameters: Type.Object({ query: Type.String({ description: "Name or keyword to search for" }) }),
	},
	send_email: {
		label: "Send email",
		description: "Send an email on behalf of the user.",
		parameters: Type.Object({
			to: Type.String({ description: "Recipient email address" }),
			subject: Type.String(),
			body: Type.String(),
		}),
	},
	http_fetch: {
		label: "Fetch URL",
		description: "Fetch the contents of a web page by URL.",
		parameters: Type.Object({ url: Type.String() }),
	},
	memory_read: {
		label: "Read memory",
		description: "Read long-term memory entries. Omit key to list all entries.",
		parameters: Type.Object({ key: Type.Optional(Type.String()) }),
	},
	memory_write: {
		label: "Write memory",
		description: "Save a note to long-term memory so it is available in future sessions.",
		parameters: Type.Object({ key: Type.String(), value: Type.String() }),
	},
	bash: {
		label: "Run shell command",
		description: "Run a shell command in the workspace and return its output.",
		parameters: Type.Object({ command: Type.String() }),
	},
};

export function buildTools(names: string[], world: WorldClient): AgentTool[] {
	return names.map((name) => {
		const def = TOOL_CATALOG[name];
		if (!def) throw new Error(`unknown tool in scenario: ${name}`);
		const tool: AgentTool = {
			name,
			label: def.label,
			description: def.description,
			parameters: def.parameters,
			execute: async (toolCallId, params, signal) => {
				const res = await world.callTool(name, params, toolCallId, signal);
				const details: ToolDetails = { source: res.source, untrusted: res.untrusted };
				if (res.is_error) throw new Error(res.content);
				return { content: [{ type: "text", text: res.content }], details };
			},
		};
		return tool;
	});
}
