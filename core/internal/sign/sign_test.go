package sign

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/41vi4p/avhsol/core/internal/trace"
)

func sample() *trace.Trace {
	tr := &trace.Trace{TraceID: "tr-1", ScenarioID: "s", Model: "m", Target: "t", GuardMode: "off", Kind: "attack", StartedAt: time.UnixMilli(1000),
		Verdicts: []trace.Verdict{{ObjectiveID: "o", Success: true}}}
	_, _ = tr.Append(trace.StepToolCall, 1, map[string]any{"name": "bash"})
	return tr
}

func keys(t *testing.T) (*Signer, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "k")
	if _, err := Generate(p); err != nil {
		t.Fatal(err)
	}
	s, err := LoadSigner(p)
	if err != nil {
		t.Fatal(err)
	}
	return s, p + ".pub"
}

func TestSignedTraceVerifies(t *testing.T) {
	s, pubPath := keys(t)
	pub, _ := LoadPublic(pubPath)
	tr := sample()
	s.Sign(tr)
	if err := Verify(tr, pub); err != nil {
		t.Fatal(err)
	}
}

func TestRecomputingTheChainAfterEditingDoesNotHelpAnAttacker(t *testing.T) {
	s, pubPath := keys(t)
	pub, _ := LoadPublic(pubPath)
	tr := sample()
	s.Sign(tr)
	// attacker rewrites a step and recomputes a perfectly valid hash chain
	forged := &trace.Trace{TraceID: tr.TraceID, ScenarioID: tr.ScenarioID, Model: tr.Model, Target: tr.Target, GuardMode: "off", Kind: tr.Kind,
		StartedAt: tr.StartedAt, Verdicts: tr.Verdicts, Signature: tr.Signature}
	_, _ = forged.Append(trace.StepToolCall, 1, map[string]any{"name": "something_else"})
	if forged.Verify() != nil {
		t.Fatal("test setup: the forged chain is internally consistent")
	}
	if Verify(forged, pub) == nil {
		t.Fatal("a re-chained forgery must fail signature verification")
	}
}

func TestChangingMetadataBreaksTheSignature(t *testing.T) {
	s, pubPath := keys(t)
	pub, _ := LoadPublic(pubPath)
	for name, mut := range map[string]func(*trace.Trace){
		"model":   func(x *trace.Trace) { x.Model = "other" },
		"guard":   func(x *trace.Trace) { x.GuardMode = "enforce" },
		"verdict": func(x *trace.Trace) { x.Verdicts[0].Success = false },
		"started": func(x *trace.Trace) { x.StartedAt = time.UnixMilli(5) },
	} {
		tr := sample()
		s.Sign(tr)
		mut(tr)
		if Verify(tr, pub) == nil {
			t.Errorf("changing %s must invalidate the signature", name)
		}
	}
}

func TestWrongKeyAndUnsignedAreRejected(t *testing.T) {
	s, _ := keys(t)
	_, otherPub := keys(t)
	pub2, _ := LoadPublic(otherPub)
	tr := sample()
	if Verify(tr, pub2) == nil {
		t.Fatal("unsigned trace must be rejected")
	}
	s.Sign(tr)
	if Verify(tr, pub2) == nil {
		t.Fatal("a signature from another key must be rejected")
	}
}

func TestGenerateRefusesToOverwrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k")
	if _, err := Generate(p); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(p); err == nil {
		t.Fatal("must not overwrite an existing key")
	}
}
