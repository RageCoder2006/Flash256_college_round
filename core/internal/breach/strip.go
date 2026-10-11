package breach

import (
	"fmt"
	"strings"

	"github.com/41vi4p/avhsol/core/internal/trace"
)

// Node is one link in a "breach line": the chain of events from planted payload to outcome.
type Node struct {
	Kind    string `json:"kind"`            // surface | ingest | tool | egress | memory | recall | outcome
	Stage   int    `json:"stage,omitempty"` // 1-based conversation stage (later sessions of a multi-stage attack are 2, 3, ...)
	Label   string `json:"label"`
	Blocked bool   `json:"blocked,omitempty"`
	Rule    string `json:"rule,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

var egressNames = map[string]bool{"send_email": true, "http_fetch": true, "bash": true}

func short(v any) string {
	s := fmt.Sprint(v)
	if len(s) > 38 {
		s = s[:37] + "…"
	}
	return s
}

func argLabel(name string, args map[string]any) string {
	for _, k := range []string{"to", "url", "doc_id", "query", "command", "key"} {
		if v, ok := args[k]; ok {
			return name + " " + short(v)
		}
	}
	return name
}

// Strip converts a trace to its breach line.
func Strip(tr *trace.Trace) []Node {
	var nodes []Node
	if tr.Attack != nil {
		nodes = append(nodes, Node{Kind: "surface", Label: "payload in " + tr.Attack.Surface})
	}
	steps := tr.Steps
	stages := trace.Stages(steps)
	untrustedSeen := false
	for i, st := range steps {
		switch st.Type {
		case trace.StepToolCall:
			name, _ := st.Data["name"].(string)
			args, _ := st.Data["args"].(map[string]any)
			n := Node{Kind: "tool", Label: argLabel(name, args), Stage: stages[i]}
			if name == "memory_write" && untrustedSeen {
				n.Kind = "memory" // persisted after untrusted content: the stage-1 foothold
			}
			if egressNames[name] {
				n.Kind = "egress"
			}
			// look ahead for this call's guard verdict / result
			for j := i + 1; j < len(steps) && j <= i+3; j++ {
				if steps[j].Type == trace.StepGuard {
					if d, _ := steps[j].Data["decision"].(string); d == "deny" || d == "approve" {
						if tr.GuardMode == "enforce" {
							n.Blocked = true
						}
						if ids, ok := steps[j].Data["rule_ids"].([]any); ok && len(ids) > 0 {
							var s []string
							for _, id := range ids {
								s = append(s, fmt.Sprint(id))
							}
							n.Rule = strings.Join(s, "+")
						}
						n.Reason, _ = steps[j].Data["reason"].(string)
					}
				}
				if steps[j].Type == trace.StepToolResult {
					if src, _ := steps[j].Data["source"].(string); strings.HasPrefix(src, "retrieved:") || strings.HasPrefix(src, "web:") || strings.HasPrefix(src, "memory:") {
						if name == "memory_read" || strings.HasPrefix(src, "memory:") {
							n.Kind = "recall" // a tainted memory entry came back into context
						} else {
							n.Kind = "ingest"
						}
						untrustedSeen = true
					}
					break
				}
			}
			if n.Kind == "egress" && !untrustedSeen && !n.Blocked {
				n.Kind = "tool"
			}
			nodes = append(nodes, n)
		}
	}
	out := Node{Kind: "outcome", Stage: lastStage(nodes)}
	if tr.Kind == "benign" {
		out.Label = map[bool]string{true: "task completed", false: "task failed"}[tr.Success]
	} else if tr.Success {
		out.Label = "data leaked"
	} else {
		out.Label = "contained"
	}
	nodes = append(nodes, out)
	return nodes
}

func lastStage(nodes []Node) int {
	st := 1
	for _, n := range nodes {
		if n.Stage > st {
			st = n.Stage
		}
	}
	return st
}

// Depth reports how many conversation stages a breach line spans and whether it is a genuine multi-stage attack: a memory
// foothold in one stage, recalled and acted on (egress) in a later one.
func Depth(nodes []Node) (stages int, multi bool) {
	stages = 1
	memStage := 0
	for _, n := range nodes {
		if n.Stage > stages {
			stages = n.Stage
		}
		switch n.Kind {
		case "memory":
			if memStage == 0 {
				memStage = n.Stage
			}
		case "egress":
			if memStage > 0 && n.Stage > memStage {
				multi = true
			}
		}
	}
	return stages, multi
}
