# Terminal interface

`avhsol` with no arguments on a terminal (or `avhsol tui`) opens menus for everything you would otherwise type as flags. With no terminal
(a pipe, CI) `avhsol` prints usage as before.

| Menu | What it does |
|---|---|
| Audit a scenario | Pick a scenario (or **b**rowse for a file): the static permission audit, in the window, no model needed |
| Attack campaign / Adaptive hunt / Validate defenses | A form: scenario, seeds, agent under test (simulated harness or a target file), guard, sandbox (Landlock or gVisor, shown only if available), repeats or budget, options, output directory. The exact command is shown before it runs |
| Fork a recorded run | Live revive: a trace id and a step |
| Status | Live CPU, memory, swap, disk, network, pressure and AVHSOL processes (same sampler as the dashboard) |
| Traces and reports | List recorded runs (breach/held/benign, signed), open one (integrity, signature, attack path with stages, every step), verify, see the evaluation, **x** saves a report and cycles html, md, json, sarif, pdf |
| Threat intelligence | Sources and counts, browse, **/** search, details, **s** sync (runs `avhsol intel sync`, audited) |
| Scenarios and targets | What can be tested and how |
| Doctor | Checks with a fix hint: model env (names only), guard, Neo4j, Qdrant, sandbox, gVisor, Chrome, signing key match, intel cache |

Keys: arrows (or j k) move, enter opens or runs, esc goes back, left/right changes a field, **b** browses for a file, ctrl+c stops a run (then quits), `?` help.
Long actions run the same `avhsol` command as a subprocess in its own process group, so cancelling also stops the sandboxed agents it started; after
a run, **e** shows the security evaluation and **t** the traces.

Remembered: your last choices, as paths and options only, in `out/.tui.json`. **Never** read or stored: the model key, API tokens, anything secret
(they come from your environment; Doctor shows only whether they are set). `NO_COLOR=1` gives a plain display. The interface is built with Bubble Tea,
Lip Gloss and Bubbles pinned to versions that build on Go 1.22 (`core/go.mod`).
