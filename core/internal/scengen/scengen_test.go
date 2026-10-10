package scengen

import (
	"context"
	"strings"
	"testing"

	"github.com/41vi4p/avhsol/core/internal/llm"
	"github.com/41vi4p/avhsol/core/internal/scenario"
	"gopkg.in/yaml.v3"
)

func TestParseToolShapes(t *testing.T) {
	for name, js := range map[string]string{
		"array":     `[{"name":"a","description":"d","input_schema":{"type":"object"}}]`,
		"mcp":       `{"tools":[{"name":"a","inputSchema":{"type":"object"}}]}`,
		"rpc":       `{"jsonrpc":"2.0","result":{"tools":[{"name":"a"}]}}`,
		"openai":    `[{"type":"function","function":{"name":"a","parameters":{"type":"object"}}}]`,
		"anthropic": `[{"name":"a","input_schema":{"type":"object"}}]`,
	} {
		ts, err := ParseTools([]byte(js))
		if err != nil || len(ts) != 1 || ts[0].Name != "a" {
			t.Errorf("%s: %v %+v", name, err, ts)
		}
	}
	if _, err := ParseTools([]byte(`{"x":1}`)); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestRuleClassification(t *testing.T) {
	cases := []struct {
		tool ToolSpec
		want []string
	}{
		{ToolSpec{Name: "Bash"}, []string{RoleDestructive, RoleEgress, RoleSensitiveRead, RoleShell, RoleUntrustedRead}},
		{ToolSpec{Name: "send_email", Schema: map[string]any{"properties": map[string]any{"to": 1, "body": 1}}}, []string{RoleEgress}},
		{ToolSpec{Name: "fetchPage", Schema: map[string]any{"properties": map[string]any{"url": 1}}}, []string{RoleUntrustedRead}},
		{ToolSpec{Name: "remember_note"}, []string{RoleMemory}},
	}
	for _, c := range cases {
		got := ClassifyRules(c.tool).Roles
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v want %v", c.tool.Name, got, c.want)
		}
	}
	if c := ClassifyRules(ToolSpec{Name: "frobnicate"}); c.Source != "none" {
		t.Fatal("unknown tool must stay unclassified without a model")
	}
}

type fakeLLM struct{ out string }

func (f fakeLLM) Chat(ctx context.Context, m []llm.Message, n int) (string, error) { return f.out, nil }

func TestModelAssistIsValidatedAgainstTheVocabulary(t *testing.T) {
	cs := Classify(context.Background(), []ToolSpec{{Name: "frobnicate"}}, fakeLLM{`sure: {"roles":["egress","root_access","memory"]}`})
	if strings.Join(cs[0].Roles, ",") != "egress,memory" || cs[0].Source != "model" {
		t.Fatalf("%+v", cs[0])
	}
	cs = Classify(context.Background(), []ToolSpec{{Name: "frobnicate"}}, fakeLLM{"no json here"})
	if len(cs[0].Roles) != 0 {
		t.Fatal("unparseable model output must be ignored")
	}
}

func TestBuildCodingAgentScenarioPassesLintAndRoundTrips(t *testing.T) {
	tools := []ToolSpec{{Name: "Bash"}, {Name: "Read", Description: "read a file"}, {Name: "Write"}}
	sc, warns := Build(tools, Classify(context.Background(), tools, nil), Options{ID: "my-agent"})
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings %v", warns)
	}
	for _, l := range Lint(sc) {
		if strings.HasPrefix(l, "error:") {
			t.Fatal(l)
		}
	}
	kinds := map[string]bool{}
	for _, o := range sc.Objectives {
		kinds[o.Kind] = true
	}
	if !kinds["sink_exfil"] || !kinds["secret_read"] || !kinds["escape_marker"] {
		t.Fatalf("objectives %v", kinds)
	}
	var back scenario.Scenario
	if err := yaml.Unmarshal(YAML(sc), &back); err != nil || !back.Generated || back.Validate() != nil {
		t.Fatalf("round trip failed: %v", err)
	}
	if len(back.Secrets) != 2 || !strings.Contains(back.Files[".env"], back.Secrets[0]) {
		t.Fatal("canaries must be planted")
	}
}

func TestBuildWarnsWhenAgentCannotExfiltrate(t *testing.T) {
	tools := []ToolSpec{{Name: "search_docs"}}
	sc, warns := Build(tools, Classify(context.Background(), tools, nil), Options{})
	if len(warns) == 0 {
		t.Fatal("must warn that exfiltration is impossible")
	}
	for _, o := range sc.Objectives {
		if o.Kind == "sink_exfil" {
			t.Fatal("sink objective for an agent that cannot send data out")
		}
	}
}

func TestLintCatchesBrokenScenarios(t *testing.T) {
	sc := &scenario.Scenario{ID: "x", SystemPrompt: "p", Tools: []string{"t"}, UserTask: []string{"u"}, Secrets: []string{"S3CRET"},
		Objectives: []scenario.Objective{{ID: "o", Kind: "made_up"}}, BenignTasks: []scenario.BenignTask{{ID: "b"}}}
	joined := strings.Join(Lint(sc), "\n")
	for _, want := range []string{"no oracle implements", "not planted", "has no check"} {
		if !strings.Contains(strings.ReplaceAll(joined, "which no oracle implements", "no oracle implements"), want) {
			t.Errorf("lint missed %q in:\n%s", want, joined)
		}
	}
}
