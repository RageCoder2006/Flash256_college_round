package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/41vi4p/avhsol/core/internal/mcpserver"
	"github.com/41vi4p/avhsol/core/internal/tools"
)

// cmdMCP serves AVHSOL's tools over MCP on stdio, for Claude Code and other harnesses:
//
//	claude mcp add avhsol -- avhsol mcp
func cmdMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	role := fs.String("role", "analyst", "what the connected client may do: viewer | analyst | operator")
	allowLaunch := fs.Bool("allow-launch", false, "also expose tools that start agents and attacks (needs role operator)")
	out := fs.String("out", "", "extra run directory to include (traces/ inside)")
	_ = fs.Parse(args)
	r := map[string]int{"viewer": tools.Viewer, "analyst": tools.Analyst, "operator": tools.Operator}[*role]
	if r == 0 {
		return fmt.Errorf("-role must be viewer, analyst or operator")
	}
	if *allowLaunch && r < tools.Operator {
		return fmt.Errorf("-allow-launch needs -role operator")
	}
	exe, _ := os.Executable()
	env := tools.Env{Exe: exe}
	if *out != "" {
		env.OutDirs = []string{*out}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	s := &mcpserver.Server{Env: env, Role: r, Allowed: func(t tools.Tool) bool { return t.Effect != tools.EffectLaunches || *allowLaunch }}
	s.OnCall = func(tool string, ok bool, note string) {
		fmt.Fprintf(os.Stderr, "avhsol mcp: %s ok=%v %s\n", tool, ok, clipStr(note, 100))
	}
	fmt.Fprintf(os.Stderr, "avhsol mcp: serving %d tools on stdio as role %s\n", len(visibleCount(s)), *role)
	return s.ServeStdio(ctx, os.Stdin, os.Stdout)
}

func visibleCount(s *mcpserver.Server) []tools.Tool {
	var out []tools.Tool
	for _, t := range tools.All() {
		if t.MinRole <= s.Role && s.Allowed(t) {
			out = append(out, t)
		}
	}
	return out
}
