package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/41vi4p/avhsol/core/internal/breach"
	"github.com/41vi4p/avhsol/core/internal/intel"
	"github.com/41vi4p/avhsol/core/internal/sign"
	"github.com/41vi4p/avhsol/core/internal/trace"
)

// ---------------------------------------------------------------- traces

type traceRow struct {
	id, kind, technique, guard, model string
	success, signed                   bool
	steps                             int
	started                           time.Time
	path                              string
}

func (m *Model) loadTraces() {
	m.traces, m.tCursor = nil, 0
	files, _ := filepath.Glob(filepath.Join(m.tDir, "traces", "*.json"))
	for _, f := range files {
		tr, err := trace.Load(f)
		if err != nil {
			continue
		}
		r := traceRow{id: tr.TraceID, kind: tr.Kind, guard: tr.GuardMode, model: tr.Model, success: tr.Success, signed: tr.Signature != nil, steps: len(tr.Steps), started: tr.StartedAt, path: f}
		if tr.Attack != nil {
			r.technique = tr.Attack.Technique
		}
		m.traces = append(m.traces, r)
	}
	sort.Slice(m.traces, func(i, j int) bool { return m.traces[i].started.After(m.traces[j].started) })
}

func (m *Model) updateTraces(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	n := len(m.traces)
	switch k.String() {
	case "esc", "q", "backspace":
		m.back()
	case "up", "k":
		if n > 0 {
			m.tCursor = (m.tCursor + n - 1) % n
		}
	case "down", "j":
		if n > 0 {
			m.tCursor = (m.tCursor + 1) % n
		}
	case "enter":
		if n > 0 {
			m.openTrace(m.traces[m.tCursor], false)
		}
	case "v":
		if n > 0 {
			m.openTrace(m.traces[m.tCursor], true)
		}
	case "e":
		m.runOut = m.tDir
		return m.showResults()
	}
	return m, nil
}

func (m *Model) openTrace(r traceRow, verifyOnly bool) {
	tr, err := trace.Load(r.path)
	if err != nil {
		m.flash = "Cannot read that trace: " + err.Error()
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s · guard %s · %s\n", sTitle.Render(tr.TraceID), tr.Kind, tr.GuardMode, tr.Model)
	if tr.Attack != nil {
		fmt.Fprintf(&b, "%s %s via %s\n", sDim.Render("attack"), tr.Attack.Technique, tr.Attack.Surface)
		if tr.Attack.IntelRef != "" {
			fmt.Fprintf(&b, "%s %s\n", sDim.Render("derived from"), tr.Attack.IntelRef)
		}
	}
	chain := "intact"
	if err := tr.Verify(); err != nil {
		chain = sBad.Render("BROKEN: " + err.Error())
	}
	sig := sWarn.Render("not signed")
	if tr.Signature != nil {
		sig = sWarn.Render("signed by " + tr.Signature.KeyID + ", not verified (no public key)")
		if pub, err := sign.LoadPublic(signingKey() + ".pub"); err == nil {
			if err := sign.Verify(tr, pub); err != nil {
				sig = sBad.Render("SIGNATURE FAILED: " + err.Error())
			} else {
				sig = sOK.Render("signature valid (" + tr.Signature.KeyID + ")")
			}
		}
	}
	fmt.Fprintf(&b, "%s %s · %s\n", sDim.Render("integrity"), chain, sig)
	if verifyOnly {
		m.stack = append(m.stack, mTraces)
		m.mode = mView
		m.setView("Verify · "+tr.TraceID, b.String())
		return
	}
	outcome := sOK.Render("held")
	switch {
	case tr.Kind == "benign" && tr.Success:
		outcome = sOK.Render("task completed")
	case tr.Kind == "benign":
		outcome = sWarn.Render("task failed")
	case tr.Success:
		outcome = sBad.Render("OBJECTIVE ACHIEVED")
	}
	fmt.Fprintf(&b, "%s %s\n", sDim.Render("outcome"), outcome)
	for _, v := range tr.Verdicts {
		mark := sDim.Render("·")
		if v.Success {
			mark = sBad.Render("✗")
		}
		fmt.Fprintf(&b, "  %s %-28s %s\n", mark, v.ObjectiveID, sDim.Render(clip(v.Evidence, 100)))
	}
	b.WriteString("\n" + sKey.Render("Attack path") + "\n")
	for _, n := range breach.Strip(tr) {
		st := ""
		if n.Stage > 1 {
			st = sDim.Render(fmt.Sprintf(" [stage %d]", n.Stage))
		}
		blocked := ""
		if n.Blocked {
			blocked = sOK.Render("  BLOCKED " + n.Rule)
		}
		fmt.Fprintf(&b, "  %-8s %s%s%s\n", n.Kind, clip(n.Label, 70), st, blocked)
	}
	b.WriteString("\n" + sKey.Render("Steps") + "\n")
	stages := trace.Stages(tr.Steps)
	for i, s := range tr.Steps {
		fmt.Fprintf(&b, "  %3d s%d %-12s %s\n", s.Seq, stages[i], s.Type, clip(stepSummary(s), max(20, m.w-28)))
	}
	m.stack = append(m.stack, mTraces)
	m.mode = mView
	m.setView("Trace · "+tr.TraceID, b.String())
}

func stepSummary(s trace.Step) string {
	d := s.Data
	str := func(k string) string { v, _ := d[k].(string); return v }
	switch s.Type {
	case trace.StepUserTurn, trace.StepLLMResponse:
		return str("text")
	case trace.StepToolCall:
		return fmt.Sprintf("%s %v", str("name"), d["args"])
	case trace.StepToolResult:
		if src := str("source"); src != "" {
			return "[" + src + "] " + str("content")
		}
		return str("content")
	case trace.StepGuard:
		return str("decision") + " " + str("reason")
	}
	return str("event")
}

func (m *Model) viewTraces() string {
	var b strings.Builder
	b.WriteString(sTitle.Render("Recorded runs") + sDim.Render("  "+m.tDir) + "\n\n")
	if len(m.traces) == 0 {
		return b.String() + sDim.Render("No traces here. Run a campaign first, or look in another output directory.")
	}
	rows := m.h - 9
	start := 0
	if m.tCursor >= rows {
		start = m.tCursor - rows + 1
	}
	for i := start; i < len(m.traces) && i < start+max(3, rows); i++ {
		t := m.traces[i]
		outcome := sOK.Render("held   ")
		if t.success {
			outcome = sBad.Render("BREACH ")
		}
		if t.kind == "benign" {
			outcome = sDim.Render("benign ")
		}
		sg := "·"
		if t.signed {
			sg = sOK.Render("✓")
		}
		line := fmt.Sprintf("%s %-12s %s %-8s %-22s %3d steps  %s", sg, t.id, outcome, t.guard, clip(t.technique, 22), t.steps, sDim.Render(t.started.Format("01-02 15:04")))
		if i == m.tCursor {
			line = sSel.Render("▸ ") + line
		} else {
			line = "  " + line
		}
		b.WriteString(clip(line, m.w+40) + "\n")
	}
	return b.String()
}

// ---------------------------------------------------------------- threat intel

type intelRow struct {
	it intel.Item
}

func (m *Model) loadIntel(q string) {
	m.iItems, m.iCursor = nil, 0
	st, err := intel.Open(intel.Dir())
	if err != nil {
		return
	}
	m.intelSrc = nil
	for _, s := range st.Sources() {
		last := "never"
		if s.LastSync != "" {
			if t, e := time.Parse(time.RFC3339, s.LastSync); e == nil {
				last = time.Since(t).Round(time.Minute).String() + " ago"
			}
		}
		m.intelSrc = append(m.intelSrc, fmt.Sprintf("%-8s %5d records   last sync %s", s.Name, s.Items, last))
	}
	for _, it := range st.Query(intel.Filter{Query: q, Limit: 60}) {
		m.iItems = append(m.iItems, intelRow{it})
	}
}

func (m *Model) updateIntel(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if m.mode == mIntelSearch {
		if ok {
			switch k.String() {
			case "esc":
				m.mode = mIntel
				m.iq.Blur()
				return m, nil
			case "enter":
				m.loadIntel(m.iq.Value())
				m.mode = mIntel
				m.iq.Blur()
				return m, nil
			}
		}
		var cmd tea.Cmd
		m.iq, cmd = m.iq.Update(msg)
		return m, cmd
	}
	if !ok {
		return m, nil
	}
	n := len(m.iItems)
	switch k.String() {
	case "esc", "q", "backspace":
		m.back()
	case "up", "k":
		if n > 0 {
			m.iCursor = (m.iCursor + n - 1) % n
		}
	case "down", "j":
		if n > 0 {
			m.iCursor = (m.iCursor + 1) % n
		}
	case "/":
		m.mode = mIntelSearch
		m.iq.Focus()
		return m, nil
	case "enter":
		if n > 0 {
			it := m.iItems[m.iCursor].it
			var b strings.Builder
			fmt.Fprintf(&b, "%s  %s · %s · %s\n", sTitle.Render(it.ID), it.Source, it.Kind, strings.ToUpper(orDefault(it.Severity, "unrated")))
			if it.KEV {
				b.WriteString(sBad.Render("Known to be exploited in the wild (CISA KEV)") + "\n")
			}
			fmt.Fprintf(&b, "\n%s\n\n%s\n\n", it.Title, sDim.Render(it.Summary))
			if it.CVSS > 0 {
				fmt.Fprintf(&b, "CVSS %.1f   ", it.CVSS)
			}
			if it.EPSS > 0 {
				fmt.Fprintf(&b, "Exploit chance %.1f%% in 30 days (EPSS)", it.EPSS*100)
			}
			if len(it.Affects) > 0 {
				fmt.Fprintf(&b, "\nAffects: %s", strings.Join(it.Affects, ", "))
			}
			if len(it.Taxon) > 0 {
				fmt.Fprintf(&b, "\nTaxonomy: %s", strings.Join(it.Taxon, ", "))
			}
			if it.URL != "" {
				fmt.Fprintf(&b, "\n\n%s", it.URL)
			}
			m.stack = append(m.stack, mIntel)
			m.mode = mView
			m.setView("Threat intel · "+it.ID, b.String())
		}
	case "s":
		m.form = nil
		argv := []string{exePath(), "intel", "sync"}
		p, err := startProc(argv)
		if err != nil {
			m.flash = err.Error()
			return m, nil
		}
		m.run, m.runLines, m.runDone, m.runErr = p, nil, false, nil
		m.runTitle, m.runCmd, m.runOut = "Threat-intel sync", "avhsol intel sync", ""
		m.view.SetContent("")
		m.stack = append(m.stack, mIntel)
		m.mode = mRun
		return m, tea.Batch(p.next(), m.spin.Tick)
	}
	return m, nil
}

func (m *Model) viewIntel() string {
	var b strings.Builder
	b.WriteString(sTitle.Render("Threat intelligence") + "\n")
	for _, s := range m.intelSrc {
		b.WriteString("  " + sDim.Render(s) + "\n")
	}
	b.WriteString("\n")
	if m.mode == mIntelSearch {
		b.WriteString(sKey.Render("Search: ") + m.iq.View() + "\n\n")
	} else if v := m.iq.Value(); v != "" {
		b.WriteString(sDim.Render("showing matches for: "+v) + "\n\n")
	}
	if len(m.iItems) == 0 {
		return b.String() + sDim.Render("Nothing here. Press s to sync the public sources.")
	}
	rows := max(3, m.h-len(m.intelSrc)-12)
	start := 0
	if m.iCursor >= rows {
		start = m.iCursor - rows + 1
	}
	for i := start; i < len(m.iItems) && i < start+rows; i++ {
		it := m.iItems[i].it
		flag := "  "
		if it.KEV {
			flag = sBad.Render("! ")
		}
		line := fmt.Sprintf("%s%-20s %-8s %s", flag, it.ID, orDefault(it.Severity, "-"), clip(it.Title, max(20, m.w-40)))
		if i == m.iCursor {
			line = sSel.Render("▸") + line
		} else {
			line = " " + line
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// ---------------------------------------------------------------- status

func (m *Model) viewStatus() string {
	var b strings.Builder
	b.WriteString(sTitle.Render("Status") + sDim.Render("  this machine, right now") + "\n\n")
	if m.mon == nil {
		return b.String()
	}
	s := m.mon.Latest()
	h := s.Host
	if !h.Supported {
		return b.String() + sWarn.Render("Host metrics are only available on Linux.")
	}
	bar := func(p float64, w int) string {
		if p < 0 {
			p = 0
		}
		if p > 100 {
			p = 100
		}
		n := int(p / 100 * float64(w))
		col := sOK
		if p > 85 {
			col = sBad
		} else if p > 60 {
			col = sWarn
		}
		return col.Render(strings.Repeat("█", n)) + sDim.Render(strings.Repeat("░", w-n))
	}
	kb := func(v uint64) string { return fmt.Sprintf("%.1f GB", float64(v)/1024/1024) }
	memP := 0.0
	if h.Mem.TotalKB > 0 {
		memP = 100 * float64(h.Mem.UsedKB) / float64(h.Mem.TotalKB)
	}
	swapP := 0.0
	if h.Mem.SwapTotalKB > 0 {
		swapP = 100 * float64(h.Mem.SwapUsedKB) / float64(h.Mem.SwapTotalKB)
	}
	w := max(10, min(40, m.w-40))
	fmt.Fprintf(&b, "  CPU      %s %5.1f%%   %d cores · load %.2f %.2f %.2f\n", bar(h.CPU, w), h.CPU, len(h.Cores), h.Load[0], h.Load[1], h.Load[2])
	fmt.Fprintf(&b, "  Memory   %s %5.1f%%   %s of %s\n", bar(memP, w), memP, kb(h.Mem.UsedKB), kb(h.Mem.TotalKB))
	fmt.Fprintf(&b, "  Swap     %s %5.1f%%   %s of %s\n", bar(swapP, w), swapP, kb(h.Mem.SwapUsedKB), kb(h.Mem.SwapTotalKB))
	for i, d := range h.Disks {
		p := 0.0
		if d.Total > 0 {
			p = 100 * float64(d.Used) / float64(d.Total)
		}
		label := "Disk"
		if i > 0 {
			label = "Runs disk"
		}
		fmt.Fprintf(&b, "  %-8s %s %5.1f%%   %.0f GB free\n", label, bar(p, w), p, float64(d.Free)/1e9)
	}
	fmt.Fprintf(&b, "  Network  ↓ %s/s   ↑ %s/s     Disk I/O  read %s/s  write %s/s\n", human(h.NetRx), human(h.NetTx), human(h.DiskRead), human(h.DiskWrite))
	if h.PSI.OK {
		fmt.Fprintf(&b, "  Pressure CPU %.1f%%  memory %.1f%%  io %.1f%%   (share of the last 10 s tasks waited)\n", h.PSI.CPU, h.PSI.Mem, h.PSI.IO)
	}
	if len(h.Cores) > 0 {
		var cs strings.Builder
		for _, c := range h.Cores {
			cs.WriteString(string("▁▂▃▄▅▆▇█"[min(7, int(c/100*8))*3 : min(7, int(c/100*8))*3+3]))
		}
		fmt.Fprintf(&b, "  Cores    %s\n", cs.String())
	}
	b.WriteString("\n" + sKey.Render("AVHSOL processes") + "\n")
	for _, p := range s.Procs {
		fmt.Fprintf(&b, "  %-12s %5.1f%% CPU   %s\n", p.Component, p.CPU, human(float64(p.RSSBytes)))
	}
	for _, c := range s.Containers {
		fmt.Fprintf(&b, "  %-26s %5.1f%% CPU   %s\n", clip(c.Name, 26), c.CPU, human(c.MemBytes))
	}
	b.WriteString("\n" + sDim.Render("Sandbox usage appears here while an agent runs from the API; runs started from this menu are separate processes.") + "\n")
	return b.String()
}

func human(n float64) string {
	u := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for n >= 1024 && i < len(u)-1 {
		n /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", n, u[i])
	}
	return fmt.Sprintf("%.1f %s", n, u[i])
}

// ---------------------------------------------------------------- scenarios and targets

func (m *Model) viewScen() string {
	var b strings.Builder
	b.WriteString(sTitle.Render("What can be tested") + "\n\n")
	for i, it := range m.scenarios {
		line := fmt.Sprintf("  %-34s %s", it.title, sDim.Render(clip(it.desc, max(10, m.w-40))))
		if i == m.sCursor {
			line = sSel.Render("▸ "+clip(fmt.Sprintf("%-34s", it.title), 36)) + " " + sDim.Render(clip(it.desc, max(10, m.w-42)))
		}
		b.WriteString(line + "\n")
	}
	if len(m.scenarios) > 0 {
		rel, _ := filepath.Rel(m.root, m.scenarios[m.sCursor].action)
		b.WriteString("\n" + sDim.Render("file: "+rel) + "\n")
		if body, err := os.ReadFile(m.scenarios[m.sCursor].action); err == nil {
			lines := strings.Split(string(body), "\n")
			if len(lines) > 8 {
				lines = lines[:8]
			}
			b.WriteString(sDim.Render(strings.Join(lines, "\n")) + "\n")
		}
	}
	return b.String()
}
