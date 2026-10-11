package whitebox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func scan(t *testing.T, dir string, o Options) *Result {
	t.Helper()
	o.Dir = dir
	if o.Intel == nil {
		t.Setenv("AVHSOL_INTEL_DIR", t.TempDir())
	}
	res, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func ids(r *Result) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range r.Report.Findings {
		m[f.ID] = f
	}
	return m
}

func toolNames(r *Result) map[string]Tool {
	m := map[string]Tool{}
	for _, tl := range r.Report.Tools {
		m[tl.Name] = tl
	}
	return m
}

func TestVulnerablePythonAgent(t *testing.T) {
	res := scan(t, "testdata/vuln-py", Options{})
	tools := toolNames(res)
	for _, n := range []string{"run_shell", "fetch_url", "read_file", "send_email"} {
		if _, ok := tools[n]; !ok {
			t.Errorf("tool %s not found: %v", n, tools)
		}
	}
	if tl := tools["run_shell"]; tl.Line == 0 || !strings.Contains(strings.Join(tl.Hints, ","), "shell") {
		t.Errorf("run_shell must be located and hinted as shell: %+v", tl)
	}
	f := ids(res)
	for _, want := range []string{"WB-TRIFECTA", "WB-SHELL-SINK", "WB-SECRET", "WB-TLS-OFF", "WB-ENV-COMMITTED", "WB-TOOL-SHELL", "WB-SQL-CONCAT", "WB-INSTRUCTION-FILES"} {
		if _, ok := f[want]; !ok {
			t.Errorf("missing finding %s; have %v", want, keys(f))
		}
	}
	if f["WB-TRIFECTA"].Severity != "critical" {
		t.Errorf("trifecta must be critical: %+v", f["WB-TRIFECTA"])
	}
	// secrets are shown as fingerprints, never in full
	for _, fd := range res.Report.Findings {
		if strings.Contains(fd.Evidence, "abcdEFGH1234ijkl") || strings.Contains(fd.Evidence, "hf_abcdefghijklmnopqrstuvwx1234") {
			t.Errorf("secret leaked into evidence: %q", fd.Evidence)
		}
	}
	if !contains(res.Report.Frameworks, "LangChain") || !contains(res.Report.Frameworks, "OpenAI SDK") {
		t.Errorf("frameworks: %v", res.Report.Frameworks)
	}
	if res.Scenario == nil || !res.Scenario.Generated || len(res.Scenario.Objectives) == 0 {
		t.Fatalf("a scenario must be generated: %+v", res.Scenario)
	}
}

func TestMCPServerAndConfig(t *testing.T) {
	res := scan(t, "testdata/mcp-ts", Options{})
	tools := toolNames(res)
	if _, ok := tools["run_command"]; !ok {
		t.Fatalf("server.tool not found: %v", tools)
	}
	f := ids(res)
	for _, want := range []string{"WB-MCP-UNPINNED", "WB-MCP-BROAD-FS", "WB-TOOL-SHELL"} {
		if _, ok := f[want]; !ok {
			t.Errorf("missing %s; have %v", want, keys(f))
		}
	}
	if !contains(res.Report.Frameworks, "MCP") {
		t.Errorf("frameworks: %v", res.Report.Frameworks)
	}
}

func TestCleanAgentRaisesNothingSerious(t *testing.T) {
	res := scan(t, "testdata/clean", Options{})
	for _, f := range res.Report.Findings {
		if sevOrder[f.Severity] <= sevOrder["medium"] {
			t.Errorf("false positive on a clean agent: %s", f.String())
		}
	}
}

func TestScanNeverWritesIntoTheDirectory(t *testing.T) {
	before := snapshot(t, "testdata")
	scan(t, "testdata/vuln-py", Options{})
	scan(t, "testdata/mcp-ts", Options{})
	if after := snapshot(t, "testdata"); after != before {
		t.Fatal("the scan changed the audited tree")
	}
}

func snapshot(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			b.WriteString(p + "|" + info.ModTime().String() + "|" + strings.Repeat("x", int(info.Size())%7) + "\n")
		}
		return nil
	})
	return b.String()
}

func TestDependenciesParsedAndOSVMatched(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1<<16)
		n, _ := r.Body.Read(buf)
		got = string(buf[:n])
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-xxxx-yyyy"}]},{},{"vulns":[{"id":"PYSEC-2018-1"}]}]}`))
	}))
	defer srv.Close()
	res := scan(t, "testdata/vuln-py", Options{Online: true, OSV: &OSV{Base: srv.URL}})
	if res.Report.DepsChecked != "online" || len(res.Report.DepFinds) != 2 {
		t.Fatalf("%s %+v", res.Report.DepsChecked, res.Report.DepFinds)
	}
	if !strings.Contains(got, `"version":"1.3.0"`) || !strings.Contains(got, `"ecosystem":"PyPI"`) {
		t.Fatalf("exact versions must be sent: %s", got)
	}
	for _, d := range res.Report.DepFinds {
		if !d.Exact {
			t.Errorf("OSV matches are exact: %+v", d)
		}
	}
}

func TestOSVMustBeHTTPS(t *testing.T) {
	if _, err := (&OSV{Base: "http://evil.example"}).Query(context.Background(), []Dep{{Name: "a", Version: "1", Ecosystem: "npm"}}); err == nil {
		t.Fatal("plain http to a remote host must be refused")
	}
}

func TestOfflineSaysVersionsAreNotChecked(t *testing.T) {
	res := scan(t, "testdata/vuln-py", Options{})
	if res.Report.DepsChecked == "online" {
		t.Fatal("must not go online by default")
	}
}

func TestSARIFAndFiles(t *testing.T) {
	res := scan(t, "testdata/vuln-py", Options{})
	dir := t.TempDir()
	if err := res.WriteFiles(dir); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"whitebox.json", "whitebox.sarif", filepath.Join("scenarios", res.Scenario.ID+".yaml")} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Error(err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "whitebox.sarif"))
	if !strings.Contains(string(b), `"version": "2.1.0"`) || !strings.Contains(string(b), "WB-SHELL-SINK") {
		t.Fatalf("sarif: %s", b)
	}
}

func TestRepoConfigBuildsATarget(t *testing.T) {
	d := t.TempDir()
	_ = os.WriteFile(filepath.Join(d, "avhsol.yaml"), []byte("name: demo\nrun: [sh, -c, \"echo {task}\"]\nmodel_env: both\n"), 0o644)
	cfg, err := LoadRepoConfig(d)
	if err != nil || cfg == nil {
		t.Fatal(err)
	}
	p := DetectProfile(d, cfg)
	if p == nil || p.Target == nil || p.Target.Env["OPENAI_BASE_URL"] != "{proxy_url}/v1" || p.Target.Env["ANTHROPIC_BASE_URL"] != "{proxy_url}" {
		t.Fatalf("%+v", p)
	}
	if len(p.Target.Command) != 3 {
		t.Fatal("run is the command")
	}
	if _, err := LoadRepoConfig(t.TempDir()); err != nil {
		t.Fatal("a missing avhsol.yaml is not an error")
	}
	_ = os.WriteFile(filepath.Join(d, "avhsol.yaml"), []byte("model_env: nonsense\nrun: [x]\n"), 0o644)
	if _, err := LoadRepoConfig(d); err == nil {
		t.Fatal("bad model_env must be rejected")
	}
}

func keys(m map[string]Finding) []string {
	var o []string
	for k := range m {
		o = append(o, k)
	}
	return o
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}
