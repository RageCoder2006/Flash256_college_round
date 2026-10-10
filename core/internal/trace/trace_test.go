package trace

import "testing"

func TestChainDetectsTamper(t *testing.T) {
	tr := &Trace{TraceID: "t1"}
	for i := 0; i < 3; i++ {
		if _, err := tr.Append(StepToolCall, int64(i), map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tr.Verify(); err != nil {
		t.Fatalf("clean trace should verify: %v", err)
	}
	head := tr.HeadHash()
	tr.Steps[1].Data["i"] = 99
	if err := tr.Verify(); err == nil {
		t.Fatal("tampered trace must fail verification")
	}
	tr.Steps[1].Data["i"] = 1
	if tr.HeadHash() != head {
		t.Fatal("head hash should be stable")
	}
}

func TestIdenticalContentIdenticalHead(t *testing.T) {
	mk := func() *Trace {
		tr := &Trace{}
		_, _ = tr.Append("a", 1, map[string]any{"x": 1, "y": "z"})
		_, _ = tr.Append("b", 2, map[string]any{"k": []string{"p"}})
		return tr
	}
	if mk().HeadHash() != mk().HeadHash() {
		t.Fatal("hash must be deterministic")
	}
}
