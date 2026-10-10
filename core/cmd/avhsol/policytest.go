package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"

	"github.com/41vi4p/avhsol/core/internal/guard"
	"github.com/41vi4p/avhsol/core/internal/revive"
	"github.com/41vi4p/avhsol/core/internal/scenario"
	"github.com/41vi4p/avhsol/core/internal/trace"
)

// cmdPolicyTest replays recorded traces through a policy. No LLM, no sandbox: just the guard's
// verdict on each recorded call with the provenance it had then. This is the regression test for
// a policy change: which past exploits would it have stopped, and which legitimate tasks would it break?
func cmdPolicyTest(args []string) error {
	fs := flag.NewFlagSet("policy-test", flag.ExitOnError)
	dirs := fs.String("traces", "out/traces", "comma-separated trace directories")
	scDir := fs.String("scenarios", "scenarios", "scenario directory (the policy is derived from each trace's scenario)")
	guardURL := fs.String("guard-url", os.Getenv("AVHSOL_GUARD_URL"), "avhsol-proxy URL")
	without := fs.String("without", "", "comma-separated defenses to switch off for this test, e.g. D6")
	only := fs.String("only", "", "comma-separated defenses to keep on (everything else off)")
	outFile := fs.String("json", "", "write the full result as JSON")
	verbose := fs.Bool("v", false, "list every uncontained exploit and false positive with its calls")
	_ = fs.Parse(args)
	if *guardURL == "" {
		return fmt.Errorf("policy-test needs -guard-url (cargo run --release -p avhsol-proxy)")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	g := guard.New(*guardURL)
	if err := g.Health(ctx); err != nil {
		return fmt.Errorf("guard not reachable at %s: %w", *guardURL, err)
	}
	defenses := guard.AllDefenses
	if *only != "" {
		defenses = strings.Split(*only, ",")
	}
	if *without != "" {
		drop := map[string]bool{}
		for _, d := range strings.Split(*without, ",") {
			drop[d] = true
		}
		var keep []string
		for _, d := range defenses {
			if !drop[d] {
				keep = append(keep, d)
			}
		}
		defenses = keep
	}
	scs := map[string]*scenario.Scenario{}
	ms, _ := filepath.Glob(filepath.Join(*scDir, "*.yaml"))
	for _, m := range ms {
		if sc, err := scenario.Load(m); err == nil {
			scs[sc.ID] = sc
		}
	}
	// group traces by scenario so the right policy is pushed once per group
	byScenario := map[string][]*trace.Trace{}
	for _, d := range strings.Split(*dirs, ",") {
		files, _ := filepath.Glob(filepath.Join(d, "*.json"))
		for _, f := range files {
			tr, err := trace.Load(f)
			if err != nil {
				continue
			}
			// unguarded attacks are what a new policy must stop; benign tasks are what it must not break.
			if (tr.Kind == "attack" && tr.GuardMode == "off") || tr.Kind == "benign" {
				byScenario[tr.ScenarioID] = append(byScenario[tr.ScenarioID], tr)
			}
		}
	}
	var all []*revive.Result
	for id, trs := range byScenario {
		sc := scs[id]
		if sc == nil {
			fmt.Fprintf(os.Stderr, "skipping %d traces of unknown scenario %q\n", len(trs), id)
			continue
		}
		if err := g.PushPolicy(ctx, guard.PolicyFromScenario(sc, defenses)); err != nil {
			return err
		}
		for _, tr := range trs {
			r, err := revive.WhatIf(ctx, g, tr)
			if err != nil {
				return err
			}
			all = append(all, r)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].TraceID < all[j].TraceID })

	var exploits, contained, benign, fps int
	for _, r := range all {
		switch {
		case r.Kind == "benign":
			benign++
			if r.FalsePositive {
				fps++
			}
		case r.ExploitRecorded:
			exploits++
			if r.ExploitContained {
				contained++
			}
		}
	}
	fmt.Printf("policy under test: defenses %v  (%d traces replayed, no model calls)\n", defenses, len(all))
	fmt.Printf("  recorded exploits contained:   %d of %d\n", contained, exploits)
	fmt.Printf("  legitimate tasks broken:       %d of %d\n", fps, benign)
	for _, r := range all {
		bad := (r.ExploitRecorded && !r.ExploitContained) || r.FalsePositive
		if !bad {
			continue
		}
		label := "UNCONTAINED EXPLOIT"
		if r.FalsePositive {
			label = "FALSE POSITIVE"
		}
		fmt.Printf("\n  %s  %s  %s %s\n", label, r.TraceID, r.Scenario, r.Technique)
		if *verbose {
			for _, c := range r.Calls {
				mark := " "
				if c.Decision != "allow" {
					mark = "x"
				}
				fmt.Printf("    %s #%d %-14s taint=%-5v %-7s %s %s\n", mark, c.Seq, c.Tool, c.Tainted, c.Decision, strings.Join(c.Rules, "+"), c.Args)
			}
		}
	}
	if *outFile != "" {
		b, _ := json.MarshalIndent(all, "", "  ")
		return os.WriteFile(*outFile, b, 0o644)
	}
	return nil
}
