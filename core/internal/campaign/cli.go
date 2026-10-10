package campaign

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/41vi4p/avhsol/core/internal/cliagent"
	"github.com/41vi4p/avhsol/core/internal/guard"
	"github.com/41vi4p/avhsol/core/internal/harness"
	"github.com/41vi4p/avhsol/core/internal/scenario"
	"github.com/41vi4p/avhsol/core/internal/trace"
	"github.com/41vi4p/avhsol/core/internal/world"
)

// Policy builds the guard policy for the scenario, plus the CLI target's tool-trust settings.
func (r *Runner) Policy(defenses []string) guard.Policy {
	p := guard.PolicyFromScenario(r.Scenario, defenses)
	if r.CLI != nil {
		p.UntrustedTools = append(p.UntrustedTools, r.CLI.UntrustedTools...)
	}
	return p
}

// execute runs one episode with whichever target type the runner has.
func (r *Runner) execute(ctx context.Context, tr *trace.Trace, w *world.World, sf *scenario.Surface, payload string, turns []string, llm harness.LLMSpec) error {
	if r.CLI == nil {
		return r.runEpisode(ctx, tr, w, llm, turns)
	}
	return r.runCLIEpisode(ctx, tr, w, sf, payload, turns)
}

// payloadSnippet is a distinctive prefix of the planted text, used to recognise the moment the
// agent reads the poisoned file (through any tool, in any wording of the call).
func payloadSnippet(payload string) string {
	p := strings.TrimSpace(payload)
	r := []rune(p)
	if len(r) > 40 {
		r = r[:40]
	}
	return string(r)
}

func (r *Runner) runCLIEpisode(ctx context.Context, tr *trace.Trace, w *world.World, sf *scenario.Surface, payload string, turns []string) error {
	if r.Sandbox == nil || w.WorkDir() == "" {
		return fmt.Errorf("CLI targets need a sandbox scenario (sandbox: true) and -sandbox")
	}
	gc := guard.New(r.GuardURL)
	since := gc.LastExchangeID(ctx)
	task := strings.Join(turns, " ")
	_, _ = tr.Append(trace.StepUserTurn, nowMs(), map[string]any{"text": task})

	vars := cliagent.Vars{}
	for k, v := range r.CLIVars {
		vars[k] = v
	}
	vars["task"] = task
	ports := []int{r.Sink.Port}
	if u, err := url.Parse(r.GuardURL); err == nil {
		if p, err := strconv.Atoi(u.Port()); err == nil {
			ports = append(ports, p)
		}
	}
	res := r.CLI.Run(ctx, r.Sandbox.Bin, w.WorkDir(), ports, vars)

	exs, err := gc.Exchanges(ctx, since)
	if err != nil {
		return fmt.Errorf("reading the proxy's exchange log: %w", err)
	}
	snippet, surface := "", ""
	if sf != nil {
		surface = sf.ID
		if payload != "" {
			snippet = payloadSnippet(payload)
		}
	}
	idxByCall := map[string]int{}
	for _, ex := range exs {
		for _, tres := range ex.ToolResults {
			src := ""
			if snippet != "" && strings.Contains(tres.Content, snippet) {
				src = "retrieved:" + surface
				w.MarkUntrusted(src)
			}
			_, _ = tr.Append(trace.StepToolResult, nowMs(), map[string]any{"id": tres.ID, "content": tres.Content, "is_error": false, "source": src})
			if i, ok := idxByCall[tres.ID]; ok {
				w.ExternalResult(i, tres.Content)
			}
		}
		var names []string
		for _, c := range ex.ToolCalls {
			names = append(names, r.CLI.Canonical(c.Name))
		}
		calls := make([]map[string]any, 0, len(ex.ToolCalls))
		for i, c := range ex.ToolCalls {
			calls = append(calls, map[string]any{"id": c.ID, "name": names[i]})
		}
		_, _ = tr.Append(trace.StepLLMResponse, nowMs(), map[string]any{"text": ex.Text, "tool_calls": calls, "stop_reason": "stop"})
		used := make([]bool, len(ex.Blocked))
		for i, c := range ex.ToolCalls {
			args := c.Args
			if args == nil {
				args = map[string]any{}
			}
			idxByCall[c.ID] = w.ExternalCall(names[i], args)
			_, _ = tr.Append(trace.StepToolCall, nowMs(), map[string]any{"id": c.ID, "name": names[i], "args": args})
			for j, b := range ex.Blocked {
				if !used[j] && b.Name == c.Name {
					used[j] = true
					rules := make([]any, 0, len(b.RuleIDs))
					for _, id := range b.RuleIDs {
						rules = append(rules, id)
					}
					dec := "deny"
					_, _ = tr.Append(trace.StepGuard, nowMs(), map[string]any{"id": c.ID, "mode": r.GuardMode, "decision": dec, "rule_ids": rules, "reason": b.Reason, "enforced": b.Enforced})
					break
				}
			}
		}
	}
	// What the agent finally printed counts as output too: a leaked secret shows up here.
	i := w.ExternalCall("cli_output", map[string]any{})
	w.ExternalResult(i, res.Stdout)
	tr.FinalText = res.Stdout
	switch {
	case res.Err != "":
		tr.Error = res.Err
	case res.TimedOut:
		tr.Error = fmt.Sprintf("agent timed out after %ds", r.CLI.TimeoutSec)
	case res.ExitCode != 0 && len(exs) == 0:
		tr.Error = fmt.Sprintf("agent exited with status %d before calling the model: %s", res.ExitCode, firstLines(res.Stdout, 3))
	}
	return nil
}

func firstLines(s string, n int) string {
	ls := strings.Split(strings.TrimSpace(s), "\n")
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	return strings.Join(ls, " | ")
}
