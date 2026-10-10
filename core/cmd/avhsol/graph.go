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
	"strconv"
	"strings"
	"time"

	"github.com/41vi4p/avhsol/core/internal/graph"
	"github.com/41vi4p/avhsol/core/internal/llm"
	"github.com/41vi4p/avhsol/core/internal/scenario"
	"github.com/41vi4p/avhsol/core/internal/sign"
	"github.com/41vi4p/avhsol/core/internal/trace"
)

func graphUsage() error {
	fmt.Fprintln(os.Stderr, `usage: avhsol graph <command>

  init                         create constraints and indexes (idempotent)
  ingest -dir out/traces       write traces into the graph and vector store
  stats                        what the graph holds
  reset -yes                   delete everything (graph and vectors)
  episodes [-n 20]             recent episodes and whether they achieved a critical objective
  why <episode>                the causal path: what tainted what, what the guard decided, which secrets were touched
  beliefs <episode> [-as-of T] what we believed about its verdicts (T = RFC3339 or epoch ms)
  history <episode>            every version of its verdicts, with both time axes
  techniques [-as-of T]        outcome per attack technique, and which defenses stopped replays
  similar "text" [-k 5] [-won] past payloads/steps close to this text (-won: only ones that worked)
  ask "question"               GraphRAG: retrieve from the vectors, expand in the graph, answer with citations`)
	return fmt.Errorf("missing or unknown graph command")
}

func cmdGraph(args []string) error {
	if len(args) == 0 {
		return graphUsage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	st, err := graph.Open(ctx, graph.LoadConfig())
	if err != nil {
		return err
	}
	defer st.Close(ctx)
	switch args[0] {
	case "init":
		if err := st.EnsureSchema(ctx); err != nil {
			return err
		}
		fmt.Println("schema ready")
		return nil
	case "ingest":
		return graphIngest(ctx, st, args[1:])
	case "reset":
		fs := flag.NewFlagSet("reset", flag.ExitOnError)
		yes := fs.Bool("yes", false, "confirm: delete ALL graph and vector data")
		_ = fs.Parse(args[1:])
		if !*yes {
			return fmt.Errorf("this deletes the whole trace graph and vector collection; re-run with -yes")
		}
		if err := st.Reset(ctx); err != nil {
			return err
		}
		ix := graph.LoadIndex()
		_ = ix.Q.DeleteCollection(ctx, ix.Collection)
		fmt.Println("graph and vectors cleared")
		return nil
	case "episodes":
		fs := flag.NewFlagSet("episodes", flag.ExitOnError)
		n := fs.Int("n", 20, "how many")
		f := addFilter(fs)
		_ = fs.Parse(args[1:])
		eps, err := st.Episodes(ctx, *n, *f)
		if err != nil {
			return err
		}
		for _, e := range eps {
			word := "-"
			if e.Kind == "attack" {
				word = map[bool]string{true: "ACHIEVED", false: "held"}[e.Won]
			}
			fmt.Printf("%-14s %-7s %-14s guard=%-8s %-9s %s  %s\n", e.ID, e.Kind, e.Scenario, e.Guard, word, graph.FormatTime(e.Start), e.Target)
		}
		return nil
	case "why":
		if len(args) < 2 {
			return fmt.Errorf("usage: avhsol graph why <episode>")
		}
		steps, err := st.Why(ctx, args[1])
		if err != nil {
			return err
		}
		if len(steps) == 0 {
			return fmt.Errorf("no such episode %s", args[1])
		}
		fmt.Print(graph.FormatPath(steps))
		return nil
	case "beliefs", "history":
		fs := flag.NewFlagSet(args[0], flag.ExitOnError)
		asOf := fs.String("as-of", "", "record time: what did we believe then")
		at := fs.String("at", "", "world time")
		if len(args) < 2 {
			return fmt.Errorf("usage: avhsol graph %s <episode>", args[0])
		}
		_ = fs.Parse(args[2:])
		var bs []graph.Belief
		if args[0] == "history" {
			bs, err = st.History(ctx, args[1])
		} else {
			c, cerr := parseClock(*at, *asOf)
			if cerr != nil {
				return cerr
			}
			bs, err = st.Beliefs(ctx, args[1], c)
		}
		if err != nil {
			return err
		}
		for _, b := range bs {
			to := "now"
			if b.RecTo != nil {
				to = graph.FormatTime(*b.RecTo)
			}
			fmt.Printf("%-30s achieved=%-5v believed %s -> %s  %s\n", b.Objective, b.Success, graph.FormatTime(b.RecFrom), to, b.Evidence)
		}
		if len(bs) == 0 {
			fmt.Println("(nothing was believed about this episode at that time)")
		}
		return nil
	case "techniques":
		fs := flag.NewFlagSet("techniques", flag.ExitOnError)
		asOf := fs.String("as-of", "", "record time")
		f := addFilter(fs)
		_ = fs.Parse(args[1:])
		c, cerr := parseClock("", *asOf)
		if cerr != nil {
			return cerr
		}
		ts, err := st.Techniques(ctx, c, *f)
		if err != nil {
			return err
		}
		for _, t := range ts {
			fmt.Printf("%-26s %d/%d  %3.0f%%  stopped by: %s\n", t.Technique, t.Succeeded, t.Episodes, t.Rate*100, strings.Join(t.StoppedBy, ", "))
		}
		return nil
	case "similar":
		fs := flag.NewFlagSet("similar", flag.ExitOnError)
		k := fs.Int("k", 5, "results")
		won := fs.Bool("won", false, "only from episodes that achieved a critical objective")
		kind := fs.String("kind", "", "payload | step")
		if len(args) < 2 {
			return fmt.Errorf("usage: avhsol graph similar \"text\"")
		}
		_ = fs.Parse(args[2:])
		hits, err := st.Similar(ctx, graph.LoadIndex(), args[1], *k, *kind, *won)
		if err != nil {
			return err
		}
		for _, h := range hits {
			fmt.Printf("%.2f  %-8s %s#%d  %-22s guard=%-7s worked=%-5v %s\n", h.Score, h.Kind, h.Episode, h.Seq, h.Technique, h.Guard, h.Succeeded, strings.ReplaceAll(clipStr(h.Text, 90), "\n", " "))
		}
		return nil
	case "ask":
		if len(args) < 2 {
			return fmt.Errorf("usage: avhsol graph ask \"question\"")
		}
		url, model := os.Getenv("AVHSOL_LLM_BASE_URL"), os.Getenv("AVHSOL_LLM_MODEL")
		if url == "" || model == "" {
			return fmt.Errorf("ask needs AVHSOL_LLM_BASE_URL and AVHSOL_LLM_MODEL")
		}
		a, err := st.Ask(ctx, graph.LoadIndex(), llm.New(url, model, os.Getenv("AVHSOL_LLM_API_KEY")), args[1])
		if err != nil {
			return err
		}
		fmt.Println(a.Text)
		fmt.Printf("\nevidence from episodes: %s\n", strings.Join(a.Episodes, ", "))
		return nil
	case "stats":
		rows, err := st.Stats(ctx)
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(rows, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	return graphUsage()
}

func graphIngest(ctx context.Context, st *graph.Store, args []string) error {
	fs := flag.NewFlagSet("graph ingest", flag.ExitOnError)
	dir := fs.String("dir", "out/traces", "directory of trace JSON files (searched recursively one level)")
	scenarios := fs.String("scenarios", "scenarios", "directory of scenario YAML (used to find secrets to redact)")
	noVec := fs.Bool("no-vectors", false, "skip Qdrant")
	allowUnsigned := fs.Bool("allow-unsigned", false, "accept traces without a valid signature even though a public key is configured")
	_ = fs.Parse(args)
	if err := st.EnsureSchema(ctx); err != nil {
		return err
	}
	scs := map[string]*scenario.Scenario{}
	ms, _ := filepath.Glob(filepath.Join(*scenarios, "*.yaml"))
	for _, m := range ms {
		if sc, err := scenario.Load(m); err == nil {
			scs[sc.ID] = sc
		}
	}
	var ix *graph.Index
	if !*noVec {
		ix = graph.LoadIndex()
		fmt.Printf("vectors: %s, collection %s\n", ix.Emb.Name(), ix.Collection)
	}
	pub, perr := sign.LoadPublic(signingKeyPath() + ".pub")
	if perr == nil {
		fmt.Printf("verifying signatures against %s.pub\n", signingKeyPath())
	}
	files, _ := filepath.Glob(filepath.Join(*dir, "*.json"))
	if len(files) == 0 {
		files, _ = filepath.Glob(filepath.Join(*dir, "traces", "*.json"))
	}
	sort.Strings(files)
	var total graph.IngestStats
	skipped, failed := 0, 0
	start := time.Now()
	for _, f := range files {
		tr, err := trace.Load(f)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "  skip %s: %v\n", filepath.Base(f), err)
			continue
		}
		if pub != nil && !*allowUnsigned {
			if verr := sign.Verify(tr, pub); verr != nil {
				failed++
				fmt.Fprintf(os.Stderr, "  REFUSED %s: %v (use -allow-unsigned for legacy traces)\n", tr.TraceID, verr)
				continue
			}
		}
		stats, err := st.IngestTrace(ctx, tr, scs[tr.ScenarioID], ix)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "  FAIL %s: %v\n", tr.TraceID, err)
			continue
		}
		if stats.Unchanged {
			skipped++
			continue
		}
		total.Steps += stats.Steps
		total.Vectors += stats.Vectors
		total.Redactions += stats.Redactions
	}
	if err := st.Relink(ctx); err != nil {
		return fmt.Errorf("linking replays: %w", err)
	}
	fmt.Printf("ingested %d traces (%d steps, %d vectors, %d secrets redacted) in %s; %d already present, %d failed\n",
		len(files)-skipped-failed, total.Steps, total.Vectors, total.Redactions, time.Since(start).Round(time.Millisecond), skipped, failed)
	if failed > 0 {
		return fmt.Errorf("%d traces failed", failed)
	}
	return nil
}

func addFilter(fs *flag.FlagSet) *graph.Filter {
	f := &graph.Filter{}
	fs.StringVar(&f.Scenario, "scenario", "", "only this scenario id")
	fs.StringVar(&f.Target, "target", "", "only this target agent")
	fs.StringVar(&f.Model, "model", "", "only this model")
	fs.BoolVar(&f.IncludeSimulated, "include-simulated", false, "also count runs of the simulated (offline) model; off by default")
	return f
}

func clipStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// parseClock accepts RFC3339 or epoch milliseconds for each axis ("" = unconstrained / now).
func parseClock(at, asOf string) (graph.Clock, error) {
	var c graph.Clock
	for _, p := range []struct {
		in  string
		dst **int64
	}{{at, &c.At}, {asOf, &c.AsOf}} {
		if p.in == "" {
			continue
		}
		if ms, err := strconv.ParseInt(p.in, 10, 64); err == nil {
			*p.dst = &ms
			continue
		}
		t, err := time.Parse(time.RFC3339, p.in)
		if err != nil {
			return c, fmt.Errorf("bad time %q: use RFC3339 (2026-10-11T09:00:00Z) or epoch milliseconds", p.in)
		}
		ms := t.UnixMilli()
		*p.dst = &ms
	}
	return c, nil
}
