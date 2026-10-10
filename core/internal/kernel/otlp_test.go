package kernel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The shape must satisfy what TRIVEKTRA's genaispan.ParseAndFilter reads: process.pid on the
// resource; execute_tool span with gen_ai.* attributes and string-encoded timestamps.
func TestSpanMatchesTrivektraShape(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/traces" || r.Method != "POST" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()
	now := time.Now()
	if err := New(srv.URL).EmitTool(context.Background(), "", "bash", 4242, now, now.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	rs := got["resourceSpans"].([]any)[0].(map[string]any)
	pid := rs["resource"].(map[string]any)["attributes"].([]any)[0].(map[string]any)
	if pid["key"] != "process.pid" || pid["value"].(map[string]any)["stringValue"] != "4242" {
		t.Fatalf("bad pid attr: %v", pid)
	}
	sp := rs["scopeSpans"].([]any)[0].(map[string]any)["spans"].([]any)[0].(map[string]any)
	if sp["name"] != "execute_tool" || len(sp["traceId"].(string)) != 32 || len(sp["spanId"].(string)) != 16 {
		t.Fatalf("bad span: %v", sp)
	}
	if _, ok := sp["startTimeUnixNano"].(string); !ok {
		t.Fatal("timestamps must be strings in OTLP JSON")
	}
}

func TestReceiverDownIsAnErrorNotAPanic(t *testing.T) {
	if err := New("http://127.0.0.1:1").EmitTool(context.Background(), "", "bash", 1, time.Now(), time.Now()); err == nil {
		t.Fatal("expected a connection error")
	}
}
