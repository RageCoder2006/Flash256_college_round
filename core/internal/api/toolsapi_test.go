package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mcpServerFor(t *testing.T, enabled bool, tokens map[Role]string) (*Server, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AVHSOL_STATE", dir)
	al, err := OpenAuditLog(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	a := &Auth{fails: map[string][]time.Time{}}
	for r, tok := range tokens {
		h := hashTok(tok)
		a.tokens = append(a.tokens, token{role: r, hash: h, id: "t"})
	}
	s := New(Config{OutDir: dir, Auth: a, Audit: al})
	if enabled {
		v := s.set.get(s.cfg)
		v.MCPEnabled = true
		if err := s.set.put(v); err != nil {
			t.Fatal(err)
		}
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func post(t *testing.T, url, tok, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, e := resp.Body.Read(buf)
		b.Write(buf[:n])
		if e != nil {
			break
		}
	}
	return resp.StatusCode, b.String()
}

func TestMCPEndpointNeedsTokenAndSwitchAndRespectsRoles(t *testing.T) {
	_, off := mcpServerFor(t, false, map[Role]string{RoleViewer: "v-token", RoleOperator: "o-token"})
	if code, _ := post(t, off.URL+"/mcp", "v-token", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); code != http.StatusServiceUnavailable {
		t.Fatalf("switched off: %d", code)
	}
	_, ts := mcpServerFor(t, true, map[Role]string{RoleViewer: "v-token", RoleOperator: "o-token"})
	if code, _ := post(t, ts.URL+"/mcp", "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	list := func(tok string) map[string]bool {
		code, body := post(t, ts.URL+"/mcp", tok, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
		if code != 200 {
			t.Fatalf("%d %s", code, body)
		}
		var m struct {
			Result struct{ Tools []struct{ Name string } }
		}
		_ = json.Unmarshal([]byte(body), &m)
		out := map[string]bool{}
		for _, x := range m.Result.Tools {
			out[x.Name] = true
		}
		return out
	}
	v, o := list("v-token"), list("o-token")
	if v["avhsol_export_report"] || !o["avhsol_export_report"] || !v["avhsol_scan_codebase"] {
		t.Fatalf("roles: viewer=%v operator=%v", v, o)
	}
	if o["avhsol_audit_codebase"] {
		t.Fatal("launch tools stay off until an administrator allows them")
	}
}

func TestToolsListingShowsExposure(t *testing.T) {
	_, ts := mcpServerFor(t, true, map[Role]string{RoleViewer: "v"})
	req, _ := http.NewRequest("GET", ts.URL+"/api/tools", nil)
	req.Header.Set("Authorization", "Bearer v")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m struct {
		Tools []struct {
			Name    string
			Effect  string
			Exposed bool `json:"mcp_exposed"`
		}
		Connect map[string]string
	}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	if len(m.Tools) < 10 || m.Connect["stdio"] == "" {
		t.Fatalf("%+v", m)
	}
	for _, x := range m.Tools {
		if x.Effect == "launches" && x.Exposed {
			t.Fatalf("%s exposed by default", x.Name)
		}
	}
}

func TestCommandLineRunsAreListedAndScoped(t *testing.T) {
	s, ts := mcpServerFor(t, false, map[Role]string{RoleViewer: "v"})
	state := os.Getenv("AVHSOL_STATE")
	tdir := filepath.Join(state, "runs", "agent-1", "dyn", "traces")
	if err := os.MkdirAll(tdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := s.runDirs()["agent-1"]; got != filepath.Join(state, "runs", "agent-1", "dyn") {
		t.Fatalf("a CLI run is the dyn directory under its run folder: %q", got)
	}
	m, err := StoreReport(filepath.Join(state, "runs", "agent-1", "dyn"), "agent-1", "json", "security-report", "t", "C", []byte("{}"), "cli")
	if err != nil || len(s.reportMetas(filepath.Join(state, "runs", "agent-1", "dyn"))) != 1 || m.File == "" {
		t.Fatalf("a report stored by the CLI must be listed: %v", err)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/traces?run=agent-1", nil)
	req.Header.Set("Authorization", "Bearer v")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", err, resp)
	}
	resp.Body.Close()
}
