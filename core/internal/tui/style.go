// Package tui is the terminal interface for AVHSOL: menus, pickers and live views that start the same audits, campaigns
// and hunts as the CLI commands, and read the same results. It holds no test logic of its own: long actions run the
// `avhsol` binary as a subprocess (exactly as the API does), short ones call the same packages the CLI calls.
package tui

import (
	"os"

	"github.com/charmbracelet/lipgloss"
)

var (
	cCoral  = lipgloss.Color("#ff5577")
	cMint   = lipgloss.Color("#35e3ac")
	cViolet = lipgloss.Color("#8f80ff")
	cCyan   = lipgloss.Color("#4dd8ff")
	cAmber  = lipgloss.Color("#ffb454")
	cInk    = lipgloss.Color("#e9effc")
	cDim    = lipgloss.Color("#7686ab")
	cLine   = lipgloss.Color("#2a3558")

	sTitle    = lipgloss.NewStyle().Bold(true).Foreground(cInk)
	sBrand    = lipgloss.NewStyle().Bold(true).Foreground(cCyan)
	sDim      = lipgloss.NewStyle().Foreground(cDim)
	sKey      = lipgloss.NewStyle().Foreground(cCyan).Bold(true)
	sSel      = lipgloss.NewStyle().Foreground(cInk).Background(lipgloss.Color("#26305a")).Bold(true)
	sOK       = lipgloss.NewStyle().Foreground(cMint)
	sWarn     = lipgloss.NewStyle().Foreground(cAmber)
	sBad      = lipgloss.NewStyle().Foreground(cCoral).Bold(true)
	sBox      = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cLine).Padding(0, 1)
	sFocusBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cViolet).Padding(0, 1)
)

// plain turns colour off when the terminal is not a colour terminal or NO_COLOR is set, so the interface stays readable in logs.
func init() {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		lipgloss.SetColorProfile(0)
	}
}

func stateStyle(state string) lipgloss.Style {
	switch state {
	case "ok":
		return sOK
	case "warn":
		return sWarn
	case "bad":
		return sBad
	}
	return sDim
}

func dot(state string) string {
	switch state {
	case "ok":
		return "●"
	case "warn", "bad":
		return "●"
	}
	return "○"
}

func clip(s string, n int) string {
	r := []rune(s)
	if n <= 1 || len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
