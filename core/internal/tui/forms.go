package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/41vi4p/avhsol/core/internal/cliagent"
	"github.com/41vi4p/avhsol/core/internal/scenario"
	"github.com/charmbracelet/lipgloss"
)

// optionSet is one choice a select field offers: the label shown, the value used on the command line, and a short description.
type option struct{ label, value, desc string }

type fieldKind int

const (
	fSelect fieldKind = iota
	fNumber
	fBool
	fText
)

type field struct {
	key     string
	label   string
	kind    fieldKind
	options []option // select
	idx     int      // select
	num     int      // number
	min     int
	max     int
	on      bool   // bool
	text    string // text
	help    string
	browse  string // select: directory to browse for a custom file ("" = no browse)
}

func (f *field) value() string {
	switch f.kind {
	case fSelect:
		if f.idx >= 0 && f.idx < len(f.options) {
			return f.options[f.idx].value
		}
	case fNumber:
		return strconv.Itoa(f.num)
	case fBool:
		if f.on {
			return "1"
		}
		return ""
	case fText:
		return f.text
	}
	return ""
}

func (f *field) display() string {
	switch f.kind {
	case fSelect:
		if f.idx >= 0 && f.idx < len(f.options) {
			return f.options[f.idx].label
		}
	case fNumber:
		return strconv.Itoa(f.num)
	case fBool:
		if f.on {
			return "yes"
		}
		return "no"
	case fText:
		return f.text
	}
	return ""
}

func (f *field) change(dir int) {
	switch f.kind {
	case fSelect:
		if n := len(f.options); n > 0 {
			f.idx = (f.idx + dir + n) % n
		}
	case fNumber:
		f.num += dir
		if f.num < f.min {
			f.num = f.min
		}
		if f.num > f.max {
			f.num = f.max
		}
	case fBool:
		f.on = !f.on
	}
}

func (f *field) set(value string) {
	for i, o := range f.options {
		if o.value == value {
			f.idx = i
			return
		}
	}
	if f.kind == fSelect && value != "" { // a path picked with Browse: add it as a choice
		f.options = append(f.options, option{label: filepath.Base(value), value: value, desc: "chosen with Browse"})
		f.idx = len(f.options) - 1
	}
}

// form is a list of fields plus the action they configure.
type form struct {
	action string // campaign | hunt | validate | fork
	title  string
	fields []*field
	cursor int
}

func (fm *form) get(key string) *field {
	for _, f := range fm.fields {
		if f.key == key {
			return f
		}
	}
	return nil
}

func (fm *form) val(key string) string {
	if f := fm.get(key); f != nil {
		return f.value()
	}
	return ""
}

// choices lists the files of one kind under the repository root, with a description read from each file.
func choices(root, dir string, withNone bool) []option {
	var out []option
	if withNone {
		out = append(out, option{label: "Simulated-tool harness", value: "", desc: "A pi agent with fake tools over synthetic data; nothing real can be touched"})
	}
	files, _ := filepath.Glob(filepath.Join(root, dir, "*.yaml"))
	sort.Strings(files)
	for _, f := range files {
		name, desc := strings.TrimSuffix(filepath.Base(f), ".yaml"), ""
		switch dir {
		case "scenarios":
			if sc, err := scenario.Load(f); err == nil {
				name, desc = sc.Name, oneLine(sc.Description, 110)
			} else {
				continue
			}
		case "targets":
			if t, err := cliagent.Load(f); err == nil {
				name, desc = t.Name, "kind "+t.Kind+" · "+t.Wire+" wire"
			} else {
				continue
			}
		}
		out = append(out, option{label: name, value: f, desc: desc})
	}
	return out
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	return clip(s, n)
}

// prefs are the choices remembered between sessions. Paths and options only: never keys or tokens.
type prefs struct {
	Values map[string]map[string]string `json:"values"` // action -> field key -> value
	OutDir string                       `json:"out_dir,omitempty"`
}

// newForm builds the form for an action, applying remembered values.
func newForm(action, root string, p prefs, gvisor bool) *form {
	scen := &field{key: "scenario", label: "Scenario", kind: fSelect, options: choices(root, "scenarios", false), browse: "scenarios", help: "What the agent is told to do and what it is allowed to touch"}
	seeds := &field{key: "seeds", label: "Attack seeds", kind: fSelect, options: choices(root, "seeds", false), browse: "seeds", help: "Starting attacks; the hunter mutates them"}
	target := &field{key: "target", label: "Agent under test", kind: fSelect, options: choices(root, "targets", true), browse: "targets", help: "The agent to attack: the simulated harness or a real command-line, MCP or HTTP agent"}
	guard := &field{key: "guard", label: "Guard", kind: fSelect, options: []option{{"off", "off", "No defenses: finds what the agent does by itself"}, {"monitor", "monitor", "Record what the guard would block"}, {"enforce", "enforce", "Block denied tool calls"}}}
	iso := &field{key: "isolation", label: "Sandbox", kind: fSelect, options: []option{{"Landlock (host kernel)", "landlock", "Fast, no root needed; shares the host kernel"}}, help: "Only applies to a real agent under test"}
	if gvisor {
		iso.options = append(iso.options, option{"gVisor (no network)", "gvisor", "Docker + runsc: user-space kernel, no network, ports tunnelled"})
	}
	offline := &field{key: "offline", label: "Simulated model", kind: fBool, help: "Tests the pipeline only. Results are labelled and never rated"}
	graphF := &field{key: "graph", label: "Record to the graph", kind: fBool, help: "Write every run into Neo4j and Qdrant"}
	out := &field{key: "out", label: "Output directory", kind: fText, text: orDefault(p.OutDir, "out"), help: "Where traces and reports go"}
	var fm *form
	switch action {
	case "codebase":
		cwd, _ := os.Getwd()
		fm = &form{action: action, title: "Audit a codebase", fields: []*field{
			{key: "dir", label: "Agent code directory", kind: fText, text: cwd, help: "The directory holding the agent's source. It is read, and run read-only in a sandbox; nothing is written there"},
			{key: "mode", label: "What to do", kind: fSelect, options: []option{{"Read the code, then attack it", "full", "Needs a model (AVHSOL_LLM_*) and a launch recipe: a recognised agent or an avhsol.yaml"}, {"Read the code only", "static", "No agent is launched and no model is needed"}}},
			{key: "repeats", label: "Repeats per attack", kind: fNumber, num: 3, min: 1, max: 20, help: "3 or more is needed before a risk rating can be given"},
			{key: "online", label: "Check dependency versions online", kind: fBool, help: "Sends package names and versions to osv.dev"},
			{key: "out", label: "Run directory", kind: fText, text: "", help: "Empty = a new directory under the AVHSOL state directory, never inside the code"}}}
	case "campaign":
		fm = &form{action: action, title: "Attack campaign", fields: []*field{scen, seeds, target, guard, iso,
			{key: "repeats", label: "Repeats per attack", kind: fNumber, num: 1, min: 1, max: 20, help: "3 or more is needed before a rating can be given"},
			{key: "regress", label: "Also run the benign tasks", kind: fBool, on: true, help: "Measures what defending costs normal work"}, offline, graphF, out}}
	case "hunt":
		fm = &form{action: action, title: "Adaptive hunt", fields: []*field{scen, seeds, target, guard, iso,
			{key: "budget", label: "Attempt budget", kind: fNumber, num: 40, min: 1, max: 500, help: "How many attacks the hunter may try"},
			{key: "vsdefense", label: "Then hunt against the guard", kind: fBool, help: "Try to get past the enforcing guard"}, offline, graphF, out}}
	case "validate":
		fm = &form{action: action, title: "Validate defenses", fields: []*field{scen, seeds, target, iso,
			{key: "ablate", label: "Ablate each defense", kind: fBool, on: true, help: "Remove one defense at a time to see which matter"}, offline, graphF, out}}
	case "fork":
		fm = &form{action: action, title: "Fork a recorded run (live revive)", fields: []*field{scen, seeds, target, guard, iso,
			{key: "trace", label: "Trace id", kind: fText, help: "A recorded run in the output directory, for example tr-1a2b3c4d. Needs a real model"},
			{key: "at", label: "Step to fork at", kind: fNumber, num: 3, min: 0, max: 500, help: "Naming a step inside a model reply re-generates that whole reply"}, graphF, out}}
	}
	if fm == nil {
		return nil
	}
	// the default scenario is the first with a sandbox; remembered values override
	for _, f := range fm.fields {
		if v, ok := p.Values[action][f.key]; ok {
			switch f.kind {
			case fSelect:
				f.set(v)
			case fNumber:
				if n, err := strconv.Atoi(v); err == nil && n >= f.min && n <= f.max {
					f.num = n
				}
			case fBool:
				f.on = v == "1"
			case fText:
				if v != "" {
					f.text = v
				}
			}
		}
	}
	return fm
}

func orDefault(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// argv builds the command line for the action. It is the single place that turns choices into flags, so what the form shows
// is exactly what runs.
func (fm *form) argv(exe string, guardURL string) []string {
	if fm.action == "codebase" { // avhsol <dir> [flags]: the directory form of the command
		a := []string{exe, orDefault(fm.val("dir"), ".")}
		if fm.val("mode") == "static" {
			a = append(a, "--static")
		}
		if r := fm.val("repeats"); r != "" {
			a = append(a, "--repeats", r)
		}
		if fm.val("online") != "" {
			a = append(a, "--online")
		}
		if o := fm.val("out"); o != "" {
			a = append(a, "--out", o)
		}
		return a // the guard proxy is started (and stopped) by the run itself unless AVHSOL_GUARD_URL names one
	}
	a := []string{exe, fm.action}
	add := func(flag, v string) {
		if v != "" {
			a = append(a, flag, v)
		}
	}
	add("-scenario", fm.val("scenario"))
	add("-seeds", fm.val("seeds"))
	if t := fm.val("target"); t != "" {
		add("-target", t)
		add("-isolation", fm.val("isolation"))
	}
	add("-out", fm.val("out"))
	if fm.val("offline") != "" {
		a = append(a, "-offline")
	}
	if fm.val("graph") != "" {
		a = append(a, "-graph")
	}
	if guardURL != "" {
		add("-guard-url", guardURL)
	}
	switch fm.action {
	case "campaign":
		if g := fm.val("guard"); g != "" && g != "off" {
			add("-guard", g)
		}
		add("-repeats", fm.val("repeats"))
		if fm.val("regress") != "" {
			a = append(a, "-regress")
		}
	case "hunt":
		add("-budget", fm.val("budget"))
		if fm.val("vsdefense") != "" {
			a = append(a, "-vs-defense")
		}
	case "validate":
		if fm.val("ablate") == "" {
			a = append(a, "-ablate=false")
		}
	case "fork":
		if g := fm.val("guard"); g != "" && g != "off" {
			add("-guard", g)
		}
		add("-trace", fm.val("trace"))
		add("-at", fm.val("at"))
	}
	return a
}

// commandLine renders argv for display, with paths relative to the repository root and nothing secret in it.
func commandLine(argv []string, root string) string {
	parts := make([]string, len(argv))
	for i, s := range argv {
		if i == 0 {
			parts[i] = "avhsol"
			continue
		}
		if rel, err := filepath.Rel(root, s); err == nil && filepath.IsAbs(s) && !strings.HasPrefix(rel, "..") {
			s = rel
		}
		parts[i] = s
	}
	return strings.Join(parts, " ")
}

func (fm *form) view(w int, focus bool) string {
	var b strings.Builder
	b.WriteString(sTitle.Render(fm.title) + "\n\n")
	lw := 0
	for _, f := range fm.fields {
		if len(f.label) > lw {
			lw = len(f.label)
		}
	}
	for i, f := range fm.fields {
		cur := i == fm.cursor
		label := fmt.Sprintf("%-*s", lw, f.label)
		val := f.display()
		if f.kind == fSelect || f.kind == fNumber || f.kind == fBool {
			val = "‹ " + val + " ›"
		}
		line := fmt.Sprintf("  %s  %s", label, val)
		if cur {
			line = sSel.Render(clip(fmt.Sprintf("▸ %s  %s", label, val), w-4))
		} else {
			line = sDim.Render(label[:0]) + clip(line, w-4)
		}
		b.WriteString(line + "\n")
	}
	if f := fm.fields[fm.cursor]; true {
		var d string
		if f.kind == fSelect && f.idx < len(f.options) {
			d = f.options[f.idx].desc
		}
		if d == "" {
			d = f.help
		}
		b.WriteString("\n" + sDim.Render(clip(d, w-4)) + "\n")
	}
	return b.String()
}

// exePath is this binary, used to run subcommands.
func exePath() string {
	if e, err := os.Executable(); err == nil {
		return e
	}
	return "avhsol"
}

var _ = lipgloss.Width
