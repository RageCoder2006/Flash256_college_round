package mcpagent

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func run(t *testing.T, spec Spec, lines ...string) []map[string]any {
	var out bytes.Buffer
	if err := Serve(strings.NewReader(strings.Join(lines, "\n")+"\n"), &out, spec); err != nil {
		t.Fatal(err)
	}
	var rs []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("bad reply %q", l)
		}
		rs = append(rs, m)
	}
	return rs
}

func TestProtocolAndPoisonInResult(t *testing.T) {
	spec := Spec{Payload: "EVIL INSTRUCTION", Poison: "result"}
	rs := run(t, spec,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_project_notes"}}`)
	if len(rs) != 3 {
		t.Fatalf("a notification must get no reply; got %d replies", len(rs))
	}
	if rs[0]["result"].(map[string]any)["protocolVersion"] != "2025-03-26" {
		t.Fatal("must echo the client's protocol version")
	}
	desc := rs[1]["result"].(map[string]any)["tools"].([]any)[0].(map[string]any)["description"].(string)
	if strings.Contains(desc, "EVIL") {
		t.Fatal("result-poisoning must leave the description clean")
	}
	text := rs[2]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "EVIL INSTRUCTION") {
		t.Fatalf("payload missing from result: %q", text)
	}
}

func TestPoisonInDescriptionOnly(t *testing.T) {
	spec := Spec{Payload: "EVIL", Poison: "description", Tools: []Tool{{Name: "t", Description: "does x {{payload}}", Result: "ok {{payload}}"}}}
	rs := run(t, spec, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"t"}}`)
	d := rs[0]["result"].(map[string]any)["tools"].([]any)[0].(map[string]any)["description"].(string)
	r := rs[1]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(d, "EVIL") || strings.Contains(r, "EVIL") {
		t.Fatalf("description=%q result=%q", d, r)
	}
}

func TestUnknownToolAndMethodGetErrors(t *testing.T) {
	rs := run(t, Spec{}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope"}}`, `{"jsonrpc":"2.0","id":2,"method":"resources/list"}`)
	if rs[0]["error"] == nil || rs[1]["error"] == nil {
		t.Fatal("expected errors")
	}
}

func TestValidate(t *testing.T) {
	if (&Spec{Poison: "everywhere"}).Validate() == nil {
		t.Fatal("bad poison accepted")
	}
}
