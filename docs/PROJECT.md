# Project

**Goal:** a platform that can break any agent a security team points it at, prove how, and report it. First target class: coding agents;
then agents in general.

**Method:** an attacker (a pi agent driven by the user's OpenAI-compatible LLM) hides instructions in the content the target reads.
Deterministic oracles check the *world* (canary secret at a canary sink, host file read from inside the sandbox, forbidden tool call).
Winners are re-run for reliability and minimised. Each is replayed through the Rust guard; benign tasks run with and without it; defenses
are ablated one at a time. `policy-test` replays recorded history through any policy offline.

**Targets:** simulated-tool agents (`scenarios/*.yaml`, fake tools over synthetic data) and closed-box CLI agents
(`targets/*.yaml`) run inside the sandbox on a decoy repo; the only route to the model is the guard proxy, so every tool call is seen.

**Honesty rules:** oracles, never the model, decide success; simulated runs are never rated; errored runs are excluded; reliability only
with ≥3 repeats; one model and small samples so far (see README "Results so far").

**Credits:** David Porathur, Rishit Baitule. pi (MIT) harness, utopia (Apache-2.0) bitemporal model, TRIVEKTRA (GPLv3) detectors.
