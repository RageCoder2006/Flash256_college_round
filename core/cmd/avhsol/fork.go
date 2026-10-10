package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/41vi4p/avhsol/core/internal/campaign"
	"github.com/41vi4p/avhsol/core/internal/guard"
	"github.com/41vi4p/avhsol/core/internal/trace"
)

type editFlags map[int]string

func (e editFlags) String() string { return fmt.Sprint(map[int]string(e)) }
func (e editFlags) Set(v string) error {
	k, text, ok := strings.Cut(v, "=")
	n, err := strconv.Atoi(k)
	if !ok || err != nil {
		return fmt.Errorf("use -edit-result SEQ=TEXT")
	}
	e[n] = text
	return nil
}

// cmdFork re-walks a recorded run and lets the live model take over from a chosen step.
func cmdFork(args []string) error {
	fs := flag.NewFlagSet("fork", flag.ExitOnError)
	c := addCommon(fs)
	traceArg := fs.String("trace", "", "the recorded run: a trace id (looked up in -out/traces) or a path to a trace file")
	at := fs.Int("at", -1, "step to fork at. Naming a step inside a model reply re-generates that whole reply; a user turn or tool result continues right after it")
	guardMode := fs.String("guard", "", "guard mode for the fork: off|monitor|enforce (default: as recorded)")
	edits := editFlags{}
	fs.Var(edits, "edit-result", "SEQ=TEXT: replace what a tool returned at step SEQ (simulated-tool runs only; repeatable)")
	_ = fs.Parse(args)
	if *traceArg == "" || *at < 0 {
		return fmt.Errorf("usage: avhsol fork -trace ID|FILE -at STEP [-guard enforce] [-edit-result SEQ=TEXT]  (needs a real model: AVHSOL_LLM_BASE_URL/AVHSOL_LLM_MODEL)")
	}
	if c.offline {
		return fmt.Errorf("a fork needs a real model; -offline cannot continue a recorded conversation")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	e, err := c.setup(ctx, *guardMode != "" || c.targetPath != "")
	if err != nil {
		return err
	}
	defer e.cleanup()
	defer e.finishGraph()

	path := *traceArg
	if _, err := os.Stat(path); err != nil {
		path = filepath.Join(e.traceDir, *traceArg+".json")
	}
	orig, err := trace.Load(path)
	if err != nil {
		return fmt.Errorf("reading the recorded run: %w", err)
	}
	if orig.ScenarioID != e.sc.ID {
		return fmt.Errorf("the recorded run is from scenario %q but -scenario is %q", orig.ScenarioID, e.sc.ID)
	}
	mode := *guardMode
	if mode != "" && mode != "off" {
		g := guard.New(c.guardURL)
		if err := g.Health(ctx); err != nil {
			return fmt.Errorf("guard not reachable at %s: %w", c.guardURL, err)
		}
		if err := g.PushPolicy(ctx, e.r.Policy(guard.AllDefenses)); err != nil {
			return err
		}
		if err := g.SetMode(ctx, mode); err != nil {
			return err
		}
	} else if c.targetPath != "" && c.guardURL != "" {
		_ = guard.New(c.guardURL).SetMode(ctx, "off")
	}
	e.r.GuardMode = mode
	tr, err := e.r.Fork(ctx, orig, *at, campaign.ForkOptions{Guard: mode, Edits: edits})
	if err != nil {
		return err
	}
	p, err := tr.Save(e.traceDir)
	if err != nil {
		return err
	}
	fmt.Printf("forked %s at step %d -> %s\n  %s\n", orig.TraceID, *at, tr.TraceID, tr.ForkNote)
	fmt.Printf("  recorded: success=%v guard=%s    fork: success=%v guard=%s   (one sample of a non-deterministic model, not a verdict)\n", orig.Success, orig.GuardMode, tr.Success, tr.GuardMode)
	for _, v := range tr.Verdicts {
		fmt.Printf("  objective %-30s achieved=%v\n", v.ObjectiveID, v.Success)
	}
	fmt.Println("  saved", p)
	return nil
}
