import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const src = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
	test: {
		globals: true,
		environment: "node",
		testTimeout: 30000,
		reporters: ["default"],
	},
	resolve: {
		conditions: ["source"],
		alias: [
			{ find: /^@earendil-works\/pi-telemetry$/, replacement: src("../telemetry/src/index.ts") },
			{ find: /^@earendil-works\/pi-agent-core$/, replacement: src("../agent/src/index.ts") },
			{ find: /^@earendil-works\/pi-ai$/, replacement: src("../ai/src/index.ts") },
		],
	},
	ssr: { resolve: { conditions: ["source"] } },
});
