package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/41vi4p/avhsol/core/internal/tools"
)

func call(t *testing.T, s *Server, in string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := s.ServeStdio(context.Background(), strings.NewReader(in+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if out.Len() > 0 {
		if err := json.Unmarshal(out.Bytes(), &m); err != nil {
			t.Fatalf("%v: %s", err, out.String())
		}
	}
	return m
}

func names(m map[string]any) map[string]bool {
	out := map[string]bool{}
	for _, x := range m["result"].(map[string]any)["tools"].([]any) {
		out[x.(map[string]any)["name"].(string)] = true
	}
	return out
}

func TestInitializeAndListMatchRegistryAndRoleGating(t *testing.T) {
	s := &Server{Role: tools.Viewer}
	init := call(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if init["result"].(map[string]any)["protocolVersion"] != protocolVersion {
		t.Fatalf("%v", init)
	}
	viewer := names(call(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if !viewer["avhsol_scan_codebase"] || viewer["avhsol_export_report"] || viewer["avhsol_audit_codebase"] {
		t.Fatalf("a viewer sees read tools only: %v", viewer)
	}
	op := names(call(t, &Server{Role: tools.Operator}, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if !op["avhsol_export_report"] || op["avhsol_audit_codebase"] {
		t.Fatalf("launch tools are off by default even for operators: %v", op)
	}
	all := names(call(t, &Server{Role: tools.Admin, Allowed: func(tools.Tool) bool { return true }}, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if len(all) != len(tools.All()) {
		t.Fatalf("with everything allowed the list equals the registry: %d vs %d", len(all), len(tools.All()))
	}
}

func TestHiddenToolCannotBeCalled(t *testing.T) {
	m := call(t, &Server{Role: tools.Viewer}, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"avhsol_audit_codebase","arguments":{"path":"."}}}`)
	if m["error"] == nil {
		t.Fatalf("must be refused like an unknown tool: %v", m)
	}
}

func TestScanResultIsLabelledUntrusted(t *testing.T) {
	s := &Server{Role: tools.Viewer}
	t.Setenv("AVHSOL_INTEL_DIR", t.TempDir())
	m := call(t, s, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"avhsol_scan_codebase","arguments":{"path":"../whitebox/testdata/vuln-py"}}}`)
	res := m["result"].(map[string]any)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "untrusted_content begins") || !strings.Contains(text, "run_shell") {
		t.Fatalf("%s", text[:200])
	}
	if _, ok := res["structuredContent"].(map[string]any)["untrusted_content"]; !ok {
		t.Fatalf("structured content must use the untrusted_content key: %v", res["structuredContent"])
	}
}

func TestBadArgumentsAreAToolErrorNotACrash(t *testing.T) {
	m := call(t, &Server{Role: tools.Viewer}, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"avhsol_scan_codebase","arguments":{"bogus":1}}}`)
	if m["result"].(map[string]any)["isError"] != true {
		t.Fatalf("%v", m)
	}
}

func TestNotificationsGetNoReply(t *testing.T) {
	var out bytes.Buffer
	_ = (&Server{Role: tools.Viewer}).ServeStdio(context.Background(), strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"), &out)
	if out.Len() != 0 {
		t.Fatal("no reply to a notification")
	}
}
