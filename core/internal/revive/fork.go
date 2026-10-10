package revive

import (
	"fmt"

	"github.com/41vi4p/avhsol/core/internal/trace"
)

// Plan says what a live fork keeps from a recorded run and what the model is asked to decide again.
//
// A fork starts at a boundary, because a model can only be asked to continue from a point where every tool call it made
// has an answer. Naming a step inside a decision (the model's reply, one of its tool calls, the guard's verdict on one)
// re-decides that whole reply; naming a user turn or a tool result continues right after it.
type Plan struct {
	FromTrace string       `json:"from_trace"`
	At        int          `json:"at"`
	Kept      []trace.Step `json:"kept"`       // recorded steps replayed unchanged (edits applied)
	Exchanges []Exchange   `json:"exchanges"`  // the kept model answers, for closed-box agents
	UserTurns int          `json:"user_turns"` // user turns already consumed by the kept steps
	Redecides string       `json:"redecides"`  // what the live model is asked to do again
	Edited    []int        `json:"edited,omitempty"`
	Boundary  int          `json:"boundary_seq"` // seq of the last kept step (-1 = nothing kept)
}

// Exchange is one recorded model answer. Names are the agent's own spelling (Bash, not bash).
type Exchange struct {
	Text      string         `json:"text"`
	ToolCalls []ExchangeCall `json:"tool_calls"`
}

type ExchangeCall struct {
	ID   string         `json:"id"`
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// PlanFork decides what to keep. edits replaces the content of a recorded tool result (counterfactual: "what if the
// document had not contained the payload"); it is only meaningful for simulated-tool runs, where results are replayed.
func PlanFork(tr *trace.Trace, at int, edits map[int]string) (*Plan, error) {
	var target *trace.Step
	for i := range tr.Steps {
		if tr.Steps[i].Seq == at {
			target = &tr.Steps[i]
		}
	}
	if target == nil {
		return nil, fmt.Errorf("trace %s has no step %d (it has %d steps)", tr.TraceID, at, len(tr.Steps))
	}
	cut := at // keep steps with seq <= cut
	redecides := ""
	switch target.Type {
	case trace.StepLLMResponse, trace.StepToolCall, trace.StepGuard:
		owner := -1
		for _, s := range tr.Steps {
			if s.Seq <= at && s.Type == trace.StepLLMResponse {
				owner = s.Seq
			}
		}
		if owner < 0 {
			return nil, fmt.Errorf("step %d is not part of a model decision", at)
		}
		cut = owner - 1
		redecides = fmt.Sprintf("the model's reply at step %d is generated again", owner)
	case trace.StepToolResult, trace.StepUserTurn:
		redecides = fmt.Sprintf("the model answers whatever came at step %d", at)
	default:
		return nil, fmt.Errorf("cannot fork at a %s step", target.Type)
	}
	// keep through cut, then drop a trailing reply whose tool calls were not all answered
	var kept []trace.Step
	for _, s := range tr.Steps {
		if s.Seq <= cut {
			kept = append(kept, s)
		}
	}
	for {
		last := -1
		for i := range kept {
			if kept[i].Type == trace.StepLLMResponse {
				last = i
			}
		}
		if last < 0 {
			break
		}
		calls := map[string]bool{}
		if cs, ok := kept[last].Data["tool_calls"].([]any); ok {
			for _, c := range cs {
				if m, ok := c.(map[string]any); ok {
					calls[str(m, "id")] = true
				}
			}
		}
		for _, s := range kept[last+1:] {
			if s.Type == trace.StepToolResult {
				delete(calls, str(s.Data, "id"))
			}
		}
		if len(calls) == 0 {
			break
		}
		kept = kept[:last]
		redecides = fmt.Sprintf("the model's reply at step %d is generated again (its tool calls were not all answered)", tr.Steps[last].Seq)
	}
	p := &Plan{FromTrace: tr.TraceID, At: at, Redecides: redecides, Boundary: -1}
	byID := map[string]trace.Step{}
	for _, s := range kept {
		if s.Type == trace.StepToolCall {
			byID[str(s.Data, "id")] = s
		}
	}
	for _, s := range kept {
		cp := s
		cp.Data = map[string]any{}
		for k, v := range s.Data {
			cp.Data[k] = v
		}
		if s.Type == trace.StepToolResult {
			if text, ok := edits[s.Seq]; ok {
				cp.Data["content"] = text
				cp.Data["edited"] = true
				p.Edited = append(p.Edited, s.Seq)
			}
		}
		if s.Type == trace.StepUserTurn {
			p.UserTurns++
		}
		if s.Type == trace.StepLLMResponse {
			ex := Exchange{Text: str(s.Data, "text")}
			if cs, ok := s.Data["tool_calls"].([]any); ok {
				for _, c := range cs {
					m, _ := c.(map[string]any)
					id := str(m, "id")
					rec := byID[id]
					name := str(m, "raw_name")
					if name == "" {
						name = str(m, "name")
					}
					args, _ := rec.Data["args"].(map[string]any)
					ex.ToolCalls = append(ex.ToolCalls, ExchangeCall{ID: id, Name: name, Args: args})
				}
			}
			p.Exchanges = append(p.Exchanges, ex)
		}
		p.Kept = append(p.Kept, cp)
		p.Boundary = s.Seq
	}
	for seq := range edits {
		found := false
		for _, e := range p.Edited {
			found = found || e == seq
		}
		if !found {
			return nil, fmt.Errorf("-edit-result %d: that step is not a tool result inside the part being replayed", seq)
		}
	}
	return p, nil
}
