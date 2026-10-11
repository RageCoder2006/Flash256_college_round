package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/41vi4p/avhsol/core/internal/home"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/41vi4p/avhsol/core/internal/audit"
	"github.com/41vi4p/avhsol/core/internal/brand"
	"github.com/41vi4p/avhsol/core/internal/cliagent"
	"github.com/41vi4p/avhsol/core/internal/eval"
	"github.com/41vi4p/avhsol/core/internal/export"
	"github.com/41vi4p/avhsol/core/internal/scenario"
	"github.com/41vi4p/avhsol/core/internal/sign"
	"github.com/41vi4p/avhsol/core/internal/sysmon"
)

type mode int

const (
	mHome mode = iota
	mForm
	mBrowse
	mAuditPick
	mView // a scrolling text view (audit result, results, scenario details, trace detail)
	mRun
	mDoctor
	mStatus
	mTraces
	mIntel
	mIntelSearch
	mExport
	mScen
	mHelp
)

type menuItem struct{ title, desc, action string }

var homeMenu = []menuItem{
	{"Audit a codebase", "Point at an AI agent's source directory: read the code, then attack it in a sandbox and write the report (same as: avhsol .)", "codebase"},
	{"Audit a scenario", "Static review of what an agent is allowed to do: over-privilege and the lethal trifecta", "audit"},
	{"Attack campaign", "Run the seed attacks against an agent, optionally with the benign regression tasks", "campaign"},
	{"Adaptive hunt", "Let the attacker search for working attacks, re-run and shrink the winners", "hunt"},
	{"Validate defenses", "Replay every working exploit through the guard and remove defenses one at a time", "validate"},
	{"Fork a recorded run", "Re-walk a run to a step and let the live model take over", "fork"},
	{"Status", "Live view of this machine and the sandbox: CPU, memory, swap, disk, network", "status"},
	{"Traces and reports", "Browse recorded runs, verify them, see the evaluation, export a report", "traces"},
	{"Threat intelligence", "Sources, search, and sync of public advisories and research", "intel"},
	{"Scenarios and targets", "What can be tested, and how", "scen"},
	{"Doctor", "Check the environment and see how to fix what is missing", "doctor"},
	{"Quit", "", "quit"},
}

// Model is the whole interface. One struct, one mode at a time, a small stack for going back.
type Model struct {
	root      string
	w, h      int
	mode      mode
	stack     []mode
	cursor    int
	prefs     prefs
	gvisor    bool
	form      *form
	pick      filepicker.Model
	pickField *field
	view      viewport.Model
	viewTitle string
	spin      spinner.Model
	run       *proc
	runLines  []string
	runTitle  string
	runCmd    string
	runDone   bool
	runErr    error
	runTook   time.Duration
	runOut    string
	status    string
	checks    []Check
	checking  bool
	mon       *sysmon.Sampler
	traces    []traceRow
	tCursor   int
	tDir      string
	intelSrc  []string
	iq        textinput.Model
	iItems    []intelRow
	iCursor   int
	exportIn  string
	flash     string
	scenarios []menuItem
	sCursor   int
	quitting  bool
}

// New builds the interface rooted at the repository directory (where scenarios/, seeds/ and targets/ live).
func New(root string) *Model {
	m := &Model{root: root, w: 100, h: 30}
	m.prefs = loadPrefs(root)
	m.gvisor = cliagent.GVisorAvailable(context.Background()) == nil
	m.spin = spinner.New()
	m.spin.Spinner = spinner.Dot
	m.spin.Style = lipgloss.NewStyle().Foreground(cCyan)
	m.view = viewport.New(100, 20)
	m.iq = textinput.New()
	m.iq.Placeholder = "search advisories, e.g. MCP command injection"
	m.iq.CharLimit = 120
	return m
}

func prefsPath(root string) string {
	if home.Installed() { // never write into the (possibly read-only) asset directory
		return filepath.Join(home.StateDir(), ".tui.json")
	}
	return filepath.Join(root, "out", ".tui.json")
}

func loadPrefs(root string) prefs {
	var p prefs
	if b, err := os.ReadFile(prefsPath(root)); err == nil {
		_ = json.Unmarshal(b, &p)
	}
	if p.Values == nil {
		p.Values = map[string]map[string]string{}
	}
	return p
}

// savePrefs remembers the form's choices. Only paths and option values are stored.
func (m *Model) savePrefs() {
	if m.form == nil {
		return
	}
	v := map[string]string{}
	for _, f := range m.form.fields {
		v[f.key] = f.value()
	}
	m.prefs.Values[m.form.action] = v
	m.prefs.OutDir = m.form.val("out")
	if b, err := json.MarshalIndent(m.prefs, "", "  "); err == nil {
		_ = os.MkdirAll(filepath.Dir(prefsPath(m.root)), 0o755)
		_ = os.WriteFile(prefsPath(m.root), b, 0o600)
	}
}

func (m *Model) Init() tea.Cmd { return nil }

func (m *Model) push(to mode) {
	m.stack = append(m.stack, m.mode)
	m.mode = to
	m.flash = ""
}

func (m *Model) back() {
	if n := len(m.stack); n > 0 {
		m.mode, m.stack = m.stack[n-1], m.stack[:n-1]
	} else {
		m.mode = mHome
	}
	m.flash = ""
	if m.mode == mStatus || m.mode == mHome {
		m.stopMon()
	}
}

func (m *Model) stopMon() {
	if m.mon != nil {
		m.mon.Stop()
		m.mon = nil
	}
}

func (m *Model) setView(title, body string) {
	m.viewTitle = title
	m.view.SetContent(body)
	m.view.GotoTop()
}

func (m *Model) resize() {
	m.view.Width, m.view.Height = max(20, m.w-4), max(5, m.h-6)
	m.pick.Height = max(5, m.h-8)
}

type checksMsg []Check
type monMsg struct{}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = v.Width, v.Height
		m.resize()
		return m, nil
	case spinner.TickMsg:
		var c tea.Cmd
		m.spin, c = m.spin.Update(v)
		return m, c
	case checksMsg:
		m.checks, m.checking = v, false
		return m, nil
	case lineMsg:
		m.runLines = append(m.runLines, string(v))
		if len(m.runLines) > 5000 {
			m.runLines = m.runLines[len(m.runLines)-4000:]
		}
		m.view.SetContent(strings.Join(m.runLines, "\n"))
		if m.view.AtBottom() || true {
			m.view.GotoBottom()
		}
		return m, m.run.next()
	case doneMsg:
		m.runDone, m.runErr, m.runTook = true, v.err, v.took
		return m, nil
	case tickMsg:
		if m.mode == mStatus {
			return m, tick(2 * time.Second)
		}
		return m, nil
	case tea.KeyMsg:
		if v.String() == "ctrl+c" {
			if m.mode == mRun && !m.runDone && m.run != nil {
				m.run.interrupt()
				m.flash = "Stopping the run… (ctrl+c again to quit)"
				return m, nil
			}
			m.quitting = true
			return m, tea.Quit
		}
	}
	switch m.mode {
	case mHome:
		return m.updateHome(msg)
	case mForm:
		return m.updateForm(msg)
	case mBrowse:
		return m.updateBrowse(msg)
	case mAuditPick:
		return m.updateForm(msg)
	case mView, mScen, mExport:
		return m.updateView(msg)
	case mRun:
		return m.updateRun(msg)
	case mDoctor:
		return m.updateSimple(msg)
	case mStatus:
		return m.updateSimple(msg)
	case mTraces:
		return m.updateTraces(msg)
	case mIntel, mIntelSearch:
		return m.updateIntel(msg)
	case mHelp:
		return m.updateSimple(msg)
	}
	return m, nil
}

func (m *Model) updateSimple(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc", "q", "backspace", "left":
			m.back()
		case "r":
			if m.mode == mDoctor {
				return m, m.startChecks()
			}
		}
	}
	return m, nil
}

func (m *Model) startChecks() tea.Cmd {
	m.checking = true
	root := m.root
	return func() tea.Msg { return checksMsg(RunChecks(context.Background(), root)) }
}

func (m *Model) updateHome(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "up", "k":
		m.cursor = (m.cursor + len(homeMenu) - 1) % len(homeMenu)
	case "down", "j":
		m.cursor = (m.cursor + 1) % len(homeMenu)
	case "q":
		m.quitting = true
		return m, tea.Quit
	case "?":
		m.push(mHelp)
	case "enter", " ", "right":
		return m.openMenu(homeMenu[m.cursor].action)
	default:
		for i, it := range homeMenu { // type the first letter to jump
			if len(k.String()) == 1 && strings.HasPrefix(strings.ToLower(it.title), k.String()) && i != m.cursor {
				m.cursor = i
				break
			}
		}
	}
	return m, nil
}

func (m *Model) openMenu(action string) (tea.Model, tea.Cmd) {
	switch action {
	case "quit":
		m.quitting = true
		return m, tea.Quit
	case "audit":
		m.form = &form{action: "audit", title: "Audit a scenario", fields: []*field{{key: "scenario", label: "Scenario", kind: fSelect, options: choices(m.root, "scenarios", false), browse: "scenarios", help: "Reviews what the agent is allowed to do. Needs no model and changes nothing."}}}
		if v, ok := m.prefs.Values["campaign"]["scenario"]; ok {
			m.form.fields[0].set(v)
		}
		m.push(mAuditPick)
	case "campaign", "hunt", "validate", "fork", "codebase":
		m.form = newForm(action, m.root, m.prefs, m.gvisor)
		m.push(mForm)
	case "status":
		m.mon = sysmon.New(sysmon.Config{Paths: []string{filepath.Join(m.root, "out")}})
		m.mon.Start()
		m.push(mStatus)
		return m, tick(2 * time.Second)
	case "traces":
		m.tDir = orDefault(m.prefs.OutDir, "out")
		m.loadTraces()
		m.push(mTraces)
	case "intel":
		m.loadIntel("")
		m.iq.SetValue("")
		m.push(mIntel)
	case "scen":
		m.scenarios = m.scenarioItems()
		m.sCursor = 0
		m.push(mScen)
	case "doctor":
		m.push(mDoctor)
		return m, m.startChecks()
	}
	return m, nil
}

func (m *Model) scenarioItems() []menuItem {
	var out []menuItem
	for _, o := range choices(m.root, "scenarios", false) {
		out = append(out, menuItem{"scenario · " + o.label, o.desc, o.value})
	}
	for _, o := range choices(m.root, "targets", false) {
		out = append(out, menuItem{"target · " + o.label, o.desc, o.value})
	}
	for _, o := range choices(m.root, "seeds", false) {
		out = append(out, menuItem{"seeds · " + o.label, o.desc, o.value})
	}
	return out
}

func (m *Model) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok || m.form == nil {
		return m, nil
	}
	fm := m.form
	f := fm.fields[fm.cursor]
	if f.kind == fText && !isNav(k.String()) {
		switch k.Type {
		case tea.KeyBackspace:
			if r := []rune(f.text); len(r) > 0 {
				f.text = string(r[:len(r)-1])
			}
			return m, nil
		case tea.KeyRunes, tea.KeySpace:
			f.text += string(k.Runes)
			return m, nil
		}
	}
	switch k.String() {
	case "esc":
		m.back()
	case "up", "shift+tab":
		fm.cursor = (fm.cursor + len(fm.fields) - 1) % len(fm.fields)
	case "down", "tab":
		fm.cursor = (fm.cursor + 1) % len(fm.fields)
	case "left", "h":
		f.change(-1)
	case "right", "l", " ":
		f.change(1)
	case "b":
		if f.kind == fSelect && f.browse != "" {
			m.pickField = f
			m.pick = filepicker.New()
			m.pick.CurrentDirectory = filepath.Join(m.root, f.browse)
			m.pick.AllowedTypes = []string{".yaml", ".yml"}
			m.pick.Height = max(5, m.h-8)
			m.pick.ShowHidden = false
			m.stack = append(m.stack, m.mode)
			m.mode = mBrowse
			return m, m.pick.Init()
		}
	case "enter", "r":
		if fm.action == "audit" {
			return m.runAudit()
		}
		return m.startRun()
	}
	return m, nil
}

func isNav(s string) bool {
	switch s {
	case "up", "down", "tab", "shift+tab", "esc", "enter", "left", "right":
		return true
	}
	return false
}

func (m *Model) updateBrowse(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "esc" {
		m.back()
		return m, nil
	}
	var cmd tea.Cmd
	m.pick, cmd = m.pick.Update(msg)
	if ok, path := m.pick.DidSelectFile(msg); ok && m.pickField != nil {
		m.pickField.set(path)
		m.pickField = nil
		m.back()
	}
	return m, cmd
}

func (m *Model) runAudit() (tea.Model, tea.Cmd) {
	path := m.form.val("scenario")
	sc, err := scenario.Load(path)
	if err != nil {
		m.flash = "Cannot load that scenario: " + err.Error()
		return m, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n\n", sTitle.Render(sc.Name), sDim.Render(oneLine(sc.Description, m.w-6)))
	fs := audit.Static(sc)
	if len(fs) == 0 {
		b.WriteString(sOK.Render("No over-privilege found in what this agent is declared to be allowed to do.") + "\n")
	}
	for _, f := range fs {
		st := sWarn
		if strings.EqualFold(f.Severity, "critical") {
			st = sBad
		}
		fmt.Fprintf(&b, "%s  %-18s %s\n    %s\n\n", st.Render(fmt.Sprintf("%-8s", strings.ToUpper(f.Severity))), f.Kind, f.Tool, sDim.Render(f.Detail))
	}
	b.WriteString(sDim.Render("Static audit only: it reads the scenario's declarations and never runs the agent.") + "\n")
	m.savePrefsFor("campaign", "scenario", path)
	m.stack = append(m.stack, mAuditPick)
	m.mode = mView
	m.setView("Audit · "+filepath.Base(path), b.String())
	return m, nil
}

func (m *Model) savePrefsFor(action, key, val string) {
	if m.prefs.Values[action] == nil {
		m.prefs.Values[action] = map[string]string{}
	}
	m.prefs.Values[action][key] = val
}

func (m *Model) startRun() (tea.Model, tea.Cmd) {
	fm := m.form
	guardURL := GuardURL()
	argv := fm.argv(exePath(), guardURL)
	if fm.action == "fork" && fm.val("trace") == "" {
		m.flash = "Enter the trace id to fork."
		return m, nil
	}
	m.savePrefs()
	p, err := startProc(argv)
	if err != nil {
		m.flash = "Could not start: " + err.Error()
		return m, nil
	}
	m.run, m.runLines, m.runDone, m.runErr = p, nil, false, nil
	m.runTitle, m.runCmd, m.runOut = fm.title, commandLine(argv, m.root), fm.val("out")
	m.view.SetContent("")
	m.stack = append(m.stack, mForm)
	m.mode = mRun
	m.flash = ""
	return m, tea.Batch(p.next(), m.spin.Tick)
}

func (m *Model) updateRun(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		var cmd tea.Cmd
		m.view, cmd = m.view.Update(msg)
		return m, cmd
	}
	switch k.String() {
	case "esc", "q":
		if m.runDone {
			m.back()
			m.stack = nil
			m.mode = mHome
		} else {
			m.flash = "A run is in progress. Press ctrl+c to stop it first."
		}
	case "e", "enter":
		if m.runDone {
			return m.showResults()
		}
	case "t":
		if m.runDone {
			m.tDir = m.runOut
			m.loadTraces()
			m.stack = append(m.stack, mRun)
			m.mode = mTraces
		}
	default:
		var cmd tea.Cmd
		m.view, cmd = m.view.Update(msg)
		return m, cmd
	}
	return m, nil
}

// Evaluate reads a run directory the way `avhsol summary` does.
func Evaluate(dir string) (eval.Evaluation, *export.Report, error) {
	o := export.Options{Dir: dir, ScenarioDir: "scenarios", NoIntel: true}
	if pub, err := sign.LoadPublic(signingKey() + ".pub"); err == nil {
		o.Pub = pub
	}
	r, err := export.Build(o)
	if err != nil {
		return eval.Evaluation{}, nil, err
	}
	return eval.Summarize(r), r, nil
}

func (m *Model) showResults() (tea.Model, tea.Cmd) {
	e, _, err := Evaluate(orDefault(m.runOut, "out"))
	body := ""
	if err != nil {
		body = sWarn.Render("No evaluation yet: "+err.Error()) + "\n"
	} else {
		body = colourEval(eval.Text(e))
	}
	m.exportIn = orDefault(m.runOut, "out")
	m.stack = append(m.stack, mRun)
	m.mode = mExport
	m.setView("Security evaluation · "+m.exportIn, body)
	return m, nil
}

func colourEval(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		switch {
		case strings.HasPrefix(l, "SECURITY EVALUATION"), strings.HasPrefix(l, "By "), strings.HasPrefix(l, "Defenses"), strings.HasPrefix(l, "This does not show"):
			l = sKey.Render(l)
		case strings.HasPrefix(l, "SIMULATED"):
			l = sBad.Render(l)
		case strings.HasPrefix(l, "Rating"):
			l = sTitle.Render(l)
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func (m *Model) updateView(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.mode == mScen {
		return m.updateScen(msg)
	}
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "esc", "q", "backspace":
		m.back()
	case "x", "e":
		if m.mode == mExport {
			return m.doExport()
		}
	default:
		var cmd tea.Cmd
		m.view, cmd = m.view.Update(msg)
		return m, cmd
	}
	return m, nil
}

// doExport writes a report for the run in the chosen format. The format cycles with each press: html, md, json, sarif, pdf.
var exportFormats = []string{"html", "md", "json", "sarif", "pdf"}
var exportNext int

func (m *Model) doExport() (tea.Model, tea.Cmd) {
	format := exportFormats[exportNext%len(exportFormats)]
	exportNext++
	o := export.Options{Dir: m.exportIn, ScenarioDir: "scenarios"}
	if pub, err := sign.LoadPublic(signingKey() + ".pub"); err == nil {
		o.Pub = pub
	}
	body, _, err := export.Generate(o, "security-report", format)
	if err != nil {
		m.flash = "Export failed: " + err.Error()
		return m, nil
	}
	dir := filepath.Join(m.exportIn, "reports")
	_ = os.MkdirAll(dir, 0o755)
	p := filepath.Join(dir, fmt.Sprintf("avhsol-report-%d.%s", time.Now().Unix(), format))
	if err := os.WriteFile(p, body, 0o644); err != nil {
		m.flash = "Could not write the report: " + err.Error()
		return m, nil
	}
	m.flash = fmt.Sprintf("Saved %s report: %s (press x again for the next format)", strings.ToUpper(format), p)
	return m, nil
}

func (m *Model) updateScen(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "esc", "q", "backspace":
		m.back()
	case "up", "k":
		m.sCursor = (m.sCursor + len(m.scenarios) - 1) % max(1, len(m.scenarios))
	case "down", "j":
		m.sCursor = (m.sCursor + 1) % max(1, len(m.scenarios))
	}
	return m, nil
}

func (m *Model) View() string {
	if m.quitting {
		return ""
	}
	head := sBrand.Render("AVHSOL") + sDim.Render("  "+brand.Tagline)
	var body, foot string
	switch m.mode {
	case mHome:
		body, foot = m.viewHome(), "↑↓ move · enter open · ? help · q quit"
	case mForm, mAuditPick:
		body = m.form.view(m.w, true)
		foot = "↑↓ field · ←→ change · b browse files · enter run · esc back"
		if m.form != nil && m.form.action != "audit" {
			body += "\n" + sDim.Render("Command: ") + clip(commandLine(m.form.argv(exePath(), GuardURL()), m.root), m.w-12) + "\n"
		}
	case mBrowse:
		body, foot = sTitle.Render("Choose a file")+"\n"+sDim.Render(m.pick.CurrentDirectory)+"\n\n"+m.pick.View(), "↑↓ move · enter select · ←/esc back"
	case mView, mExport:
		body = sTitle.Render(m.viewTitle) + "\n" + m.view.View()
		foot = "↑↓ scroll · esc back"
		if m.mode == mExport {
			foot = "↑↓ scroll · x save a report (cycles format) · esc back"
		}
	case mRun:
		body, foot = m.viewRun(), "↑↓ scroll · ctrl+c stop"
		if m.runDone {
			foot = "e evaluation · t traces · esc menu"
		}
	case mDoctor:
		body, foot = m.viewDoctor(), "r re-check · esc back"
	case mStatus:
		body, foot = m.viewStatus(), "updates every 2 s · esc back"
	case mTraces:
		body, foot = m.viewTraces(), "↑↓ move · enter details · v verify · e evaluation · esc back"
	case mIntel, mIntelSearch:
		body, foot = m.viewIntel(), "↑↓ move · enter details · / search · s sync (asks first) · esc back"
	case mScen:
		body, foot = m.viewScen(), "↑↓ move · esc back"
	case mHelp:
		body, foot = m.viewHelp(), "esc back"
	}
	if m.flash != "" {
		foot = sWarn.Render(clip(m.flash, m.w-2)) + "\n" + sDim.Render(foot)
	} else {
		foot = sDim.Render(foot)
	}
	// pad every row to the full window so nothing from the previous screen can show through on any terminal
	return lipgloss.NewStyle().Width(max(20, m.w)).Height(max(5, m.h)).Render(lipgloss.JoinVertical(lipgloss.Left, head, "", body, "", foot))
}

func (m *Model) viewHome() string {
	var b strings.Builder
	for i, it := range homeMenu {
		line := fmt.Sprintf("  %-26s %s", it.title, sDim.Render(clip(it.desc, max(10, m.w-32))))
		if i == m.cursor {
			line = sSel.Render(clip(fmt.Sprintf("▸ %-26s", it.title), 30)) + " " + sDim.Render(clip(it.desc, max(10, m.w-34)))
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func (m *Model) viewRun() string {
	state := m.spin.View() + " running"
	if m.runDone {
		if m.runErr != nil {
			state = sBad.Render("✗ finished with an error: " + m.runErr.Error())
		} else {
			state = sOK.Render("✓ finished")
		}
		state += sDim.Render(fmt.Sprintf("  (%s)", m.runTook.Round(time.Second)))
	} else if m.run != nil {
		state += sDim.Render(fmt.Sprintf("  %s", time.Since(m.run.start).Round(time.Second)))
	}
	return sTitle.Render(m.runTitle) + "  " + state + "\n" + sDim.Render(clip(m.runCmd, m.w-2)) + "\n\n" + m.view.View()
}

func (m *Model) viewDoctor() string {
	var b strings.Builder
	b.WriteString(sTitle.Render("Doctor") + "\n\n")
	if m.checking && len(m.checks) == 0 {
		return b.String() + sDim.Render("checking…")
	}
	for _, c := range m.checks {
		b.WriteString(fmt.Sprintf("%s %-20s %s\n", stateStyle(c.State).Render(dot(c.State)), c.Label, c.Detail))
		if c.Fix != "" && c.State != "ok" {
			b.WriteString("    " + sDim.Render("→ "+c.Fix) + "\n")
		}
	}
	return b.String()
}

func (m *Model) viewHelp() string {
	return sTitle.Render("Help") + `

  Menus      ↑↓ (or j k) move · enter open · esc go back · q quit
  Forms      ↑↓ choose a field · ←→ change it · type to edit text · b browse for a file · enter run
  Runs       a run is the same as running the avhsol command shown above it; ctrl+c stops it
  Results    after a run: e shows the evaluation, t browses its traces
  Reports    in the evaluation view, x saves a report and cycles html, md, json, sarif, pdf

  Secrets    the model key and tokens are never read or stored here; they come from your environment
  Colour     set NO_COLOR=1 for a plain display`
}

// Run starts the interface on the terminal.
func Run(root string) error {
	p := tea.NewProgram(New(root), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

var _ = sort.Strings
