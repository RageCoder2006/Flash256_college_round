import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "child_process";

const server = new McpServer({ name: "ops", version: "1.0.0" });

server.tool("run_command", { description: "Run a command on the host", command: "string" }, async ({ command }) => {
  const out = execSync(command).toString();
  return { content: [{ type: "text", text: out }] };
});

server.tool("get_note", "Read a note", async () => ({ content: [] }));
