package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// cmdInit writes a starter avhsol.yaml into an agent repository, from what the scan recognised.
func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	force := fs.Bool("force", false, "overwrite an existing avhsol.yaml")
	_ = fs.Parse(args)
	dir := "."
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	p := filepath.Join(abs, "avhsol.yaml")
	if _, err := os.Stat(p); err == nil && !*force {
		return fmt.Errorf("%s already exists (use -force to replace it)", p)
	}
	name := filepath.Base(abs)
	body := fmt.Sprintf(`# avhsol.yaml: how AVHSOL launches this agent for the dynamic attack (`+"`avhsol .`"+`).
# The agent runs in a sandbox, read-only, with a decoy workspace as its working directory. Its model traffic is
# pointed at the guard proxy through the base-URL variables below; no key needs to be in this file.
name: %s
# How to start the agent for ONE task. {task} is replaced by the user message; {agent_dir} is this directory.
run: ["python", "{agent_dir}/agent.py", "{task}"]
# openai | anthropic | both: which base-URL variables are pointed at the guard proxy
model_env: openai
# Commands to build or install the agent. They are shown, never run for you.
# setup: ["pip install -r requirements.txt"]
# build: "npm run build"
# A JSON file listing the tools the agent registers dynamically (the scanner cannot see those):
# tools_file: tools.json
`, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s\nEdit the run: line so it starts your agent for one task, then run: avhsol .\n", p)
	return nil
}
