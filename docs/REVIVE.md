# Live revive (fork)

`avhsol fork -trace ID -at STEP [-guard enforce] [-edit-result SEQ=TEXT]` re-walks a recorded run up to just before a step and lets the live
model take over, optionally with a different guard mode or an edited tool result. The result is a **new trace** with `fork_of`, `fork_at`,
`fork_note`, linked in the graph by a `FORKED_FROM` edge. API: `POST /api/graph/episodes/{id}/fork` (operator, audited).

* **Boundary.** A model can only continue from a point where every tool call has an answer. Naming a step inside a model reply (the reply, one of its
  tool calls, the guard's verdict) re-generates that whole reply; naming a user turn or tool result continues right after it.
* **Simulated-tool runs:** the recorded steps become the conversation history in the harness (`history` on the episode spec) and their tool calls are
  re-run on a fresh world so its state matches. `-edit-result` replaces a recorded tool result (for example "what if the document had no payload").
* **Closed-box CLI agents:** the proxy serves the recorded model answers for the replayed part (`/v1/guard/cassette`) and the agent re-executes its
  own tools; the live model takes over afterwards. Edits are not possible here.
* **Honesty:** the model's output after the fork is not deterministic, so each fork is **one sample**, never a verdict. A fork needs a real model
  (`-offline` is refused), is refused for black-box HTTP targets, and the oracles judge the whole run including the replayed prefix.
* **Verified here** with a scripted OpenAI-compatible mock model: an exploited run forked at the exfiltration call with the guard enforcing was blocked,
  forked at the README with the payload removed it was not exploited, and the closed-box cassette path replayed the first exchange then blocked the second.
  Then run once against the real model with the pi agent (see STATUS.md), which found and fixed a workspace-path bug in the cassette.
