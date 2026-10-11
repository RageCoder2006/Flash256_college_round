package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/charmbracelet/x/term"

	"github.com/41vi4p/avhsol/core/internal/tui"
)

// repoRoot finds the directory holding scenarios/: the working directory, or the one above the binary's own directory (core/bin).
func repoRoot() string {
	var cands []string
	if wd, err := os.Getwd(); err == nil {
		cands = append(cands, wd, filepath.Dir(wd))
	}
	if exe, err := os.Executable(); err == nil {
		d := filepath.Dir(exe)
		cands = append(cands, filepath.Dir(filepath.Dir(d)), filepath.Dir(d), d)
	}
	for _, c := range cands {
		if fi, err := os.Stat(filepath.Join(c, "scenarios")); err == nil && fi.IsDir() {
			return c
		}
	}
	wd, _ := os.Getwd()
	return wd
}

func isTerminal() bool {
	return term.IsTerminal(os.Stdin.Fd()) && term.IsTerminal(os.Stdout.Fd())
}

func cmdTUI(args []string) error {
	if !isTerminal() {
		return fmt.Errorf("the terminal interface needs an interactive terminal; use the commands directly (avhsol -h)")
	}
	root := repoRoot()
	if err := os.Chdir(root); err != nil { // the interface and the commands it starts use repository-relative paths
		return err
	}
	return tui.Run(root)
}
