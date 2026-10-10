package graph

import (
	"strings"
	"testing"
)

func i64(v int64) *int64 { return &v }

func TestRecordAxisDefaultsToNow(t *testing.T) {
	w, p := Clock{}.Where("a", State)
	if !strings.Contains(w, "a.rec_to IS NULL") || len(p) != 0 {
		t.Fatalf("now-read must use the open-row filter and no params: %s %v", w, p)
	}
}

func TestAsOfBoundsBothEndsOfTheRecordInterval(t *testing.T) {
	w, p := Clock{AsOf: i64(500)}.Where("v", State)
	for _, want := range []string{"v.rec_from <= $v_asof", "v.rec_to IS NULL OR v.rec_to > $v_asof"} {
		if !strings.Contains(w, want) {
			t.Fatalf("missing %q in %s", want, w)
		}
	}
	if p["v_asof"] != int64(500) {
		t.Fatalf("params %v", p)
	}
}

func TestStateIsAnIntervalAndEventIsAPointInTime(t *testing.T) {
	ws, _ := Clock{At: i64(10)}.Where("a", State)
	we, _ := Clock{At: i64(10)}.Where("a", Event)
	if !strings.Contains(ws, "a.valid_to IS NULL OR a.valid_to > $a_at") {
		t.Fatalf("state must respect the end of its interval: %s", ws)
	}
	if strings.Contains(we, "valid_to") || !strings.Contains(we, "a.valid_from <= $a_at") {
		t.Fatalf("an event is part of the world from the moment it names: %s", we)
	}
}

func TestNoWorldConstraintMeansEveryMoment(t *testing.T) {
	w, _ := Clock{}.Where("a", Event)
	if strings.Contains(w, "$a_at") {
		t.Fatalf("unexpected world constraint: %s", w)
	}
}

func TestAliasesDoNotCollide(t *testing.T) {
	_, p1 := Clock{At: i64(1), AsOf: i64(2)}.Where("x", State)
	_, p2 := Clock{At: i64(1), AsOf: i64(2)}.Where("y", State)
	merged := map[string]any{}
	merge(merged, p1)
	merge(merged, p2)
	if len(merged) != 4 {
		t.Fatalf("params collided: %v", merged)
	}
}
