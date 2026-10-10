package graph

import (
	"context"
	"fmt"
	"strings"
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

func TestOverviewContainsTheEpisodeAndWhatItTouches(t *testing.T) {
	st, ctx := openOrSkip(t)
	id := fmt.Sprintf("itest-%d", time.Now().UnixNano())
	cleanup(t, st, ctx, id)
	tr := fakeTrace(id, true)
	if _, err := st.IngestTrace(ctx, tr, nil, nil); err != nil {
		t.Fatal(err)
	}
	g, err := st.Overview(ctx, Filter{Scenario: id + "-sc", IncludeSimulated: true}, 10)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, n := range g.Nodes {
		have[n.ID] = true
	}
	for _, want := range []string{"ep:" + id, "tech:" + id + "-tech", "tool:read_document", "tool:send_email"} {
		if !have[want] {
			t.Errorf("overview is missing %s (have %v)", want, have)
		}
	}
	var planted bool
	for _, e := range g.Edges {
		if e.From == "ep:"+id && e.Type == "PLANTED" {
			planted = true
		}
	}
	if !planted {
		t.Fatal("the episode must be linked to its payload")
	}
}

func TestActivationIsStrongestAtTheHitAndFadesWithDistance(t *testing.T) {
	st, ctx := openOrSkip(t)
	id := fmt.Sprintf("itest-%d", time.Now().UnixNano())
	other := id + "x"
	cleanup(t, st, ctx, id)
	for _, e := range []string{id, other} {
		if _, err := st.IngestTrace(ctx, fakeTrace(e, true), nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	// the query matched the send_email call (step 3) of the first episode
	act, err := st.Activate(ctx, []SimilarHit{{Kind: "step", Episode: id, Seq: 3, Score: 0.9}})
	if err != nil {
		t.Fatal(err)
	}
	lvl := map[string]float64{}
	for _, a := range act {
		lvl[a.ID] = a.Level
	}
	hit, neighbour, far := lvl[id+"#3"], lvl[id+"#2"], lvl[id+"#1"]
	if !(hit == 1 && neighbour > far && neighbour < hit && far > 0) {
		t.Fatalf("activation must fade with distance: hit=%.2f neighbour(1 hop)=%.2f far(2 hops)=%.2f", hit, neighbour, far)
	}
	if lvl["ep:"+id] <= 0 || lvl["tech:"+id+"-tech"] <= 0 {
		t.Fatalf("the owning episode and its technique must light up: %v", lvl)
	}
	for k := range lvl {
		if strings.Contains(k, other) {
			t.Fatalf("an unrelated episode must stay dark, but %s is active", k)
		}
	}
}
