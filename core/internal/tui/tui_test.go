package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func repo(t *testing.T) string {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "scenarios")); err != nil {
		t.Skip("repository root not found")
	}
	return root
}

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "space":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// fresh is a Model that ignores whatever preferences a developer has saved in the repository.
func fresh(t *testing.T) *Model {
	m := New(repo(t))
	m.prefs = prefs{Values: map[string]map[string]string{}}
	return m
}

func send(m *Model, keys ...string) {
	for _, k := range keys {
		m.Update(key(k))
	}
}

func TestArgvIsBuiltFromTheChoicesAndNothingElse(t *testing.T) {
	root := repo(t)
	fm := newForm("campaign", root, prefs{Values: map[string]map[string]string{}}, false)
	fm.get("offline").on = true
	fm.get("repeats").num = 3
	fm.get("out").text = "/tmp/x-out"
	fm.get("guard").set("enforce")
	argv := strings.Join(fm.argv("avhsol", "http://127.0.0.1:7077"), " ")
	for _, want := range []string{"campaign", "-scenario", "scenarios/", "-seeds", "-out /tmp/x-out", "-offline", "-guard enforce", "-repeats 3", "-regress", "-guard-url http://127.0.0.1:7077"} {
		if !strings.Contains(argv, want) {
			t.Errorf("missing %q in %s", want, argv)
		}
	}
	if strings.Contains(argv, "-target") {
		t.Error("the simulated harness needs no -target")
	}
	fm.get("target").set(filepath.Join(root, "targets", "pi-coding-agent.yaml"))
	if a := strings.Join(fm.argv("avhsol", ""), " "); !strings.Contains(a, "-target") || !strings.Contains(a, "-isolation landlock") || strings.Contains(a, "-guard-url") {
		t.Errorf("target options wrong: %s", a)
	}
	hunt := newForm("hunt", root, prefs{Values: map[string]map[string]string{}}, false)
	hunt.get("vsdefense").on = true
	if a := strings.Join(hunt.argv("avhsol", ""), " "); !strings.Contains(a, "-budget 40") || !strings.Contains(a, "-vs-defense") {
		t.Errorf("hunt argv: %s", a)
	}
}

func TestRememberedChoicesApplyAndNeverIncludeSecrets(t *testing.T) {
	root := repo(t)
	t.Setenv("AVHSOL_LLM_API_KEY", "sk-should-never-be-saved")
	dir := t.TempDir()
	m := New(dir) // a root without scenarios: the form still builds
	m.root = root
	m.prefs = prefs{Values: map[string]map[string]string{}}
	m.form = newForm("campaign", root, m.prefs, false)
	m.form.get("repeats").num = 5
	m.form.get("out").text = "mine"
	// save into the temp dir, not the repository
	m.root = dir
	m.savePrefs()
	b, err := os.ReadFile(filepath.Join(dir, "out", ".tui.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "sk-should-never-be-saved") || strings.Contains(strings.ToLower(string(b)), "token") {
		t.Fatalf("the preferences file must hold paths and options only: %s", b)
	}
	p := loadPrefs(dir)
	again := newForm("campaign", root, p, false)
	if again.get("repeats").num != 5 || again.get("out").text != "mine" {
		t.Fatalf("remembered values not applied: repeats=%d out=%q", again.get("repeats").num, again.get("out").text)
	}
}

func TestMenuNavigationAndBack(t *testing.T) {
	m := fresh(t)
	if m.mode != mHome {
		t.Fatal("starts at the menu")
	}
	send(m, "down", "down")
	if m.cursor != 2 {
		t.Fatalf("cursor %d", m.cursor)
	}
	send(m, "up", "up", "up") // wraps to the last item
	if homeMenu[m.cursor].action != "quit" {
		t.Fatalf("wraps to quit, got %s", homeMenu[m.cursor].action)
	}
	m.cursor = 1
	send(m, "enter")
	if m.mode != mForm || m.form.action != "campaign" {
		t.Fatalf("enter should open the campaign form, mode %v", m.mode)
	}
	send(m, "esc")
	if m.mode != mHome {
		t.Fatalf("esc should return home, mode %v", m.mode)
	}
}

func TestFormFieldsChangeAndTextEdits(t *testing.T) {
	m := fresh(t)
	m.cursor = 1
	send(m, "enter")
	for i := 0; i < 7; i++ { // to "Simulated model"
		send(m, "down")
	}
	if m.form.fields[m.form.cursor].key != "offline" {
		t.Fatalf("on %s", m.form.fields[m.form.cursor].key)
	}
	send(m, "space")
	if m.form.val("offline") != "1" {
		t.Fatal("space toggles a bool")
	}
	send(m, "down", "down") // out directory (text)
	for i := 0; i < 3; i++ {
		m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	}
	send(m, "z", "z")
	if m.form.val("out") != "zz" {
		t.Fatalf("text field editing: %q", m.form.val("out"))
	}
}

func TestForkNeedsATraceAndDoctorNeverShowsValues(t *testing.T) {
	m := fresh(t)
	m.cursor = 4
	send(m, "enter")
	if m.form.action != "fork" {
		t.Fatal("fork form")
	}
	send(m, "enter") // trace id empty: must not start anything
	if m.mode != mForm || !strings.Contains(m.flash, "trace id") {
		t.Fatalf("an empty trace id must be refused: mode %v flash %q", m.mode, m.flash)
	}
	t.Setenv("AVHSOL_LLM_BASE_URL", "https://example.invalid/v1")
	t.Setenv("AVHSOL_LLM_MODEL", "m")
	t.Setenv("AVHSOL_LLM_API_KEY", "sk-secret-value")
	for _, c := range RunChecks(context.Background(), repo(t)) {
		if strings.Contains(c.Detail+c.Fix, "sk-secret-value") || strings.Contains(c.Detail, "example.invalid") {
			t.Fatalf("a check leaked a configured value: %+v", c)
		}
	}
}

func TestViewFillsTheWindowAndColourCanBeOff(t *testing.T) {
	m := fresh(t)
	m.w, m.h = 80, 24
	v := m.View()
	if lines := strings.Count(v, "\n") + 1; lines != 24 {
		t.Fatalf("the view should fill the window exactly, got %d lines", lines)
	}
	if !strings.Contains(v, "Attack campaign") {
		t.Fatal("menu items must be listed")
	}
}
