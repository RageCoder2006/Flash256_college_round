#!/usr/bin/env node
// stdio JSON-RPC server. One JSON object per line in, one per line out.
// stdout is reserved for protocol lines; all logging goes to stderr.
import { createInterface } from "node:readline";
import type { CraftRequest, EpisodeSpec, RpcEvent, RpcRequest, RpcResponse } from "./protocol.ts";
import { craftPayload } from "./attacker.ts";
import { runEpisode } from "./target.ts";

function send(msg: RpcResponse | RpcEvent) {
	process.stdout.write(`${JSON.stringify(msg)}\n`);
}

async function handle(req: RpcRequest) {
	try {
		switch (req.method) {
			case "ping":
				send({ id: req.id, result: "pong" });
				return;
			case "runEpisode": {
				const spec = req.params as EpisodeSpec;
				const result = await runEpisode(spec, (step) =>
					send({ event: "step", episode_id: spec.episode_id, step }),
				);
				send({ id: req.id, result });
				return;
			}
			case "craftPayload":
				send({ id: req.id, result: await craftPayload(req.params as CraftRequest) });
				return;
			default:
				send({ id: req.id, error: `unknown method: ${req.method}` });
		}
	} catch (e) {
		send({ id: req.id, error: e instanceof Error ? e.message : String(e) });
	}
}

const rl = createInterface({ input: process.stdin });
const inflight = new Set<Promise<void>>();
rl.on("line", (line) => {
	if (!line.trim()) return;
	let req: RpcRequest;
	try {
		req = JSON.parse(line) as RpcRequest;
	} catch (e) {
		console.error("bad request line:", e);
		return;
	}
	const p = handle(req).finally(() => inflight.delete(p));
	inflight.add(p);
});
rl.on("close", () => {
	// stdin closed by the control plane: finish in-flight episodes, then exit.
	void Promise.allSettled([...inflight]).then(() => process.exit(0));
});
