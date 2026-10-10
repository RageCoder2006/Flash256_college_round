package campaign

import (
	"context"
	"fmt"
	"time"

	"github.com/41vi4p/avhsol/core/internal/audit"
	"github.com/41vi4p/avhsol/core/internal/guard"
	"github.com/41vi4p/avhsol/core/internal/harness"
	"github.com/41vi4p/avhsol/core/internal/oracle"
	"github.com/41vi4p/avhsol/core/internal/revive"
	"github.com/41vi4p/avhsol/core/internal/trace"
)

// ForkOptions are the changes a live fork makes relative to the recorded run.
type ForkOptions struct {
	Guard string         // "" keeps the runner's guard mode; off|monitor|enforce changes it
	Edits map[int]string // replace the content of a recorded tool result (simulated-tool runs only)
}

// forkRun is set on the runner for the duration of one Fork call.
type forkRun struct {
	plan *revive.Plan
	turn []string // every user turn of the original conversation
}

// Fork re-walks a recorded run up to just before step `at` and lets the live model take over from there, optionally with
// a different guard mode or an edited tool result. The new trace links back to the original (ForkOf/ForkAt).
//
// For simulated-tool runs the recorded steps are replayed as the conversation history and their tool calls are re-run on
// a fresh world, so the world is in the state it was in at that point. For closed-box CLI agents the guard proxy serves
// the recorded model answers for the replayed part (a cassette) and the agent re-executes its own tools.
// The model's output after the fork point is not deterministic: a fork is one sample, not a verdict.
func (r *Runner) Fork(ctx context.Context, orig *trace.Trace, at int, o ForkOptions) (*trace.Trace, error) {
	if r.Offline {
		return nil, fmt.Errorf("a live fork needs a real model; the simulated model cannot continue a recorded conversation")
	}
	if r.CLI != nil && r.CLI.Kind == "http" {
		return nil, fmt.Errorf("a black-box HTTP agent cannot be forked: AVHSOL does not see its model traffic")
	}
	if r.CLI != nil && len(o.Edits) > 0 {
		return nil, fmt.Errorf("-edit-result works only for simulated-tool runs: a closed-box agent produces its own tool results")
	}
	plan, err := revive.PlanFork(orig, at, o.Edits)
	if err != nil {
		return nil, err
	}
	var sfID, payload string
	if orig.Attack != nil {
		sfID, payload = orig.Attack.Surface, orig.Attack.Payload
	}
	sf := r.Scenario.Surface(sfID)
	if orig.Kind == "attack" && sf == nil {
		return nil, fmt.Errorf("the original attack used surface %q, which scenario %s does not have", sfID, r.Scenario.ID)
	}
	if o.Guard != "" {
		prev := r.GuardMode
		r.GuardMode = o.Guard
		defer func() { r.GuardMode = prev }()
	}
	tr := r.newTrace(orig.Kind, orig.UserTurns)
	tr.ForkOf, tr.ForkAt = orig.TraceID, at
	tr.ForkNote = plan.Redecides
	if len(o.Edits) > 0 {
		tr.ForkNote += fmt.Sprintf("; tool result(s) %v edited", plan.Edited)
	}
	if orig.Attack != nil {
		a := *orig.Attack
		tr.Attack = &a
	}
	w, err := r.newWorld(tr.TraceID)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	if sf != nil && payload != "" {
		if err := w.PlantPayload(sf, payload); err != nil {
			return nil, err
		}
	}
	r.fork = &forkRun{plan: plan, turn: orig.UserTurns}
	defer func() { r.fork = nil }()
	if r.CLI != nil && r.GuardURL != "" {
		gc := guard.New(r.GuardURL)
		var ex []map[string]any
		for _, e := range plan.Exchanges {
			calls := make([]map[string]any, 0, len(e.ToolCalls))
			for _, c := range e.ToolCalls {
				calls = append(calls, map[string]any{"id": c.ID, "name": c.Name, "args": c.Args})
			}
			ex = append(ex, map[string]any{"text": e.Text, "tool_calls": calls})
		}
		if err := gc.SetCassette(ctx, ex); err != nil {
			return nil, fmt.Errorf("loading the recorded answers into the proxy: %w", err)
		}
		defer func() { _ = gc.SetCassette(context.Background(), nil) }()
	}
	start := time.Now()
	if err := r.execute(ctx, tr, w, sf, payload, orig.UserTurns, r.llmFor(nil)); err != nil {
		return nil, err
	}
	recordSandbox(tr, w)
	tr.Verdicts = oracle.Evaluate(r.Scenario, w)
	tr.Success = oracle.AnySuccess(tr.Verdicts)
	tr.Progress, tr.ProgressNote = oracle.Progress(r.Scenario, tr, tr.Verdicts)
	tr.Findings = audit.Dynamic(r.Scenario, w)
	tr.DurationMs = time.Since(start).Milliseconds()
	r.finish(tr)
	return tr, nil
}

func toHarnessSteps(steps []trace.Step) []harness.Step {
	out := make([]harness.Step, 0, len(steps))
	for _, s := range steps {
		out = append(out, harness.Step{Type: s.Type, TS: s.TS, Data: s.Data})
	}
	return out
}
