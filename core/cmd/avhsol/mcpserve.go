package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/41vi4p/avhsol/core/internal/mcpagent"
)

// cmdMCPServe is not run by people: an mcp target registers it as the agent's MCP server.
func cmdMCPServe(args []string) error {
	fs := flag.NewFlagSet("mcp-serve", flag.ExitOnError)
	specPath := fs.String("spec", "", "spec file written by the runner for this episode")
	_ = fs.Parse(args)
	if *specPath == "" {
		return fmt.Errorf("usage: avhsol mcp-serve -spec FILE (started by an mcp target, not by hand)")
	}
	spec, err := mcpagent.LoadSpec(*specPath)
	if err != nil {
		return err
	}
	return mcpagent.Serve(os.Stdin, os.Stdout, spec)
}
