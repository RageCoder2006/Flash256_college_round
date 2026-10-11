package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirArgRoutesDirectoriesNotCommands(t *testing.T) {
	d := t.TempDir()
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	_ = os.Chdir(d)
	_ = os.MkdirAll(filepath.Join(d, "audit"), 0o755) // a directory named like a command must not shadow it
	_ = os.MkdirAll(filepath.Join(d, "myagent"), 0o755)
	for arg, want := range map[string]bool{".": true, "myagent": true, "./audit": true, "audit": false, "campaign": false, "--static": false, "": false, "missing": false} {
		if got := dirArg(arg); got != want {
			t.Errorf("dirArg(%q) = %v, want %v", arg, got, want)
		}
	}
}
