package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/41vi4p/avhsol/core/internal/llm"
	"github.com/41vi4p/avhsol/core/internal/scengen"
)

func cmdScengen(args []string) error {
	fs := flag.NewFlagSet("scengen", flag.ExitOnError)
	toolsFile := fs.String("tools", "", "JSON file with the agent's tools (array, MCP tools/list, OpenAI or Anthropic format)")
	mcp := fs.String("mcp", "", `MCP server command to list tools from over stdio, e.g. -mcp "npx -y @modelcontextprotocol/server-filesystem /tmp" (only tools/list is called)`)
	id := fs.String("id", "generated-agent", "scenario id")
	name := fs.String("name", "", "scenario name")
	out := fs.String("o", "", "write the scenario here (default: print to stdout)")
	assist := fs.Bool("model-assist", false, "ask the model about tools the rules cannot place (needs AVHSOL_LLM_BASE_URL and AVHSOL_LLM_MODEL)")
	_ = fs.Parse(args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var tools []scengen.ToolSpec
	var err error
	switch {
	case *toolsFile != "":
		b, rerr := os.ReadFile(*toolsFile)
		if rerr != nil {
			return rerr
		}
		tools, err = scengen.ParseTools(b)
	case *mcp != "":
		tools, err = scengen.ListMCP(ctx, strings.Fields(*mcp))
	default:
		return fmt.Errorf("give the agent's tools with -tools FILE or -mcp \"COMMAND\"")
	}
	if err != nil {
		return err
	}
	var m scengen.Chatter
	if *assist {
		u, mod := os.Getenv("AVHSOL_LLM_BASE_URL"), os.Getenv("AVHSOL_LLM_MODEL")
		if u == "" || mod == "" {
			return fmt.Errorf("-model-assist needs AVHSOL_LLM_BASE_URL and AVHSOL_LLM_MODEL")
		}
		m = llm.New(u, mod, os.Getenv("AVHSOL_LLM_API_KEY"))
	}
	classes := scengen.Classify(ctx, tools, m)
	fmt.Fprintf(os.Stderr, "%d tools:\n", len(tools))
	for _, c := range classes {
		roles := strings.Join(c.Roles, ", ")
		if roles == "" {
			roles = "(unclassified: treated as harmless)"
		}
		fmt.Fprintf(os.Stderr, "  %-24s %-8s %s\n", c.Tool, "["+c.Source+"]", roles)
	}
	sc, warns := scengen.Build(tools, classes, scengen.Options{ID: *id, Name: *name})
	for _, w := range warns {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	bad := 0
	for _, l := range scengen.Lint(sc) {
		fmt.Fprintln(os.Stderr, "lint:", l)
		if strings.HasPrefix(l, "error:") {
			bad++
		}
	}
	if bad > 0 {
		return fmt.Errorf("the generated scenario has %d error(s); not written", bad)
	}
	y := scengen.YAML(sc)
	if *out == "" {
		_, err = os.Stdout.Write(y)
		return err
	}
	if err := os.WriteFile(*out, y, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (use it with: avhsol campaign -scenario %s -target targets/<agent>.yaml ...)\n", *out, *out)
	return nil
}
