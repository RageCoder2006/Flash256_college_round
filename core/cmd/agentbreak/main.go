// agentbreak: autonomous AI red-team control plane.
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
	"time"

	"net/http"

	"github.com/41vi4p/agentbreak/core/internal/advisory"
	"github.com/41vi4p/agentbreak/core/internal/api"
	"github.com/41vi4p/agentbreak/core/internal/attacker"
	"github.com/41vi4p/agentbreak/core/internal/audit"
	"github.com/41vi4p/agentbreak/core/internal/campaign"
	"github.com/41vi4p/agentbreak/core/internal/guard"
	"github.com/41vi4p/agentbreak/core/internal/harness"
	"github.com/41vi4p/agentbreak/core/internal/kernel"
	"github.com/41vi4p/agentbreak/core/internal/llm"
	"github.com/41vi4p/agentbreak/core/internal/scenario"
	"github.com/41vi4p/agentbreak/core/internal/trace"
	"github.com/41vi4p/agentbreak/core/internal/world"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage: agentbreak <command> [flags]

commands:
  audit      static permission audit of a scenario
  campaign   run seed attacks (and optionally the benign regression suite)
  report     LLM-written advisories for confirmed exploits (explanation only; verdicts stay deterministic)
  serve      dashboard API (traces, reports, guard control, launch runs)
  hunt       autonomous adaptive attack search (bandit + LLM payload crafting + minimisation)
  validate   baseline attacks -> replay under the Rust guard -> benign regression -> ablation
  verify     verify the hash chain of a saved trace

run "agentbreak <command> -h" for flags.`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "audit":
		err = cmdAudit(os.Args[2:])
	case "campaign":
		err = cmdCampaign(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "hunt":
		err = cmdHunt(os.Args[2:])
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func cmdAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	scPath := fs.String("scenario", "scenarios/hr-records.yaml", "scenario file")
	_ = fs.Parse(args)
	sc, err := scenario.Load(*scPath)
	if err != nil {
		return err
	}
	fs2 := audit.Static(sc)
	if len(fs2) == 0 {
		fmt.Println("no static permission findings")
	}
	for _, f := range fs2 {
		fmt.Printf("[%s] %-22s %-14s %s\n", strings.ToUpper(f.Severity), f.Kind, f.Tool, f.Detail)
	}
	return nil
}

func cmdVerify(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: agentbreak verify <trace.json>")
	}
	tr, err := trace.Load(args[0])
	if err != nil {
		return err
	}
	if err := tr.Verify(); err != nil {
		return err
	}
	fmt.Printf("OK  %s  steps=%d  head=%s\n", tr.TraceID, len(tr.Steps), tr.HeadHash())
	return nil
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

type common struct {
	scPath, seedPath, outDir, guardURL, harnessCmd, llmURL, llmModel, llmKey string
	sandboxBin, kernelURL                                                    string
	repeats                                                                  int
	offline                                                                  bool
}

func addCommon(fs *flag.FlagSet) *common {
	c := &common{}
	fs.StringVar(&c.scPath, "scenario", "scenarios/hr-records.yaml", "scenario file")
	fs.StringVar(&c.seedPath, "seeds", "seeds/seeds.yaml", "seed corpus")
	fs.StringVar(&c.outDir, "out", "out", "output directory for traces and report")
	fs.IntVar(&c.repeats, "repeats", 1, "runs per seed×surface")
	fs.BoolVar(&c.offline, "offline", false, "SIMULATED gullible model (pipeline test; not a security result)")
	fs.StringVar(&c.guardURL, "guard-url", os.Getenv("AGENTBREAK_GUARD_URL"), "abguard-proxy base URL, e.g. http://127.0.0.1:7077")
	fs.StringVar(&c.harnessCmd, "harness", envOr("AGENTBREAK_HARNESS_CMD", "node pi/packages/agentbreak/src/rpc.ts"), "command that starts the TS harness")
	fs.StringVar(&c.llmURL, "llm-url", os.Getenv("AGENTBREAK_LLM_BASE_URL"), "OpenAI-compatible base URL (…/v1)")
	fs.StringVar(&c.llmModel, "llm-model", os.Getenv("AGENTBREAK_LLM_MODEL"), "model id")
	fs.StringVar(&c.sandboxBin, "sandbox", envOr("AGENTBREAK_SANDBOX", "guard/target/release/absandbox"), "absandbox binary (used when the scenario has sandbox: true)")
	fs.StringVar(&c.kernelURL, "kernel-otlp", os.Getenv("AGENTBREAK_KERNEL_OTLP"), "TRIVEKTRA OTLP receiver (e.g. http://127.0.0.1:4318): emit a span per sandboxed tool call")
	fs.StringVar(&c.llmKey, "llm-key", os.Getenv("AGENTBREAK_LLM_API_KEY"), "API key (if any)")
	return c
}

type env struct {
	r        *campaign.Runner
	sc       *scenario.Scenario
	seeds    []campaign.Seed
	traceDir string
	cleanup  func()
}

func (c *common) setup(ctx context.Context, needGuard bool) (*env, error) {
	if !c.offline && (c.llmURL == "" || c.llmModel == "") {
		return nil, fmt.Errorf("need -llm-url and -llm-model (or AGENTBREAK_LLM_BASE_URL / AGENTBREAK_LLM_MODEL), or pass -offline")
	}
	if needGuard && c.guardURL == "" {
		return nil, fmt.Errorf("this command needs -guard-url (start the Rust guard: cargo run -p abguard-proxy)")
	}
	sc, err := scenario.Load(c.scPath)
	if err != nil {
		return nil, err
	}
	seeds, err := campaign.LoadSeeds(c.seedPath)
	if err != nil {
		return nil, err
	}
	ws := world.NewServer()
	worldURL, err := ws.Start()
	if err != nil {
		return nil, err
	}
	hc, err := harness.Start(strings.Fields(c.harnessCmd))
	if err != nil {
		ws.Close()
		return nil, err
	}
	cleanup := func() { hc.Close(); ws.Close() }
	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := hc.Ping(pctx); err != nil {
		cleanup()
		return nil, fmt.Errorf("harness not responding: %w", err)
	}
	llmBase := c.llmURL
	if c.guardURL != "" && !c.offline {
		llmBase = strings.TrimRight(c.guardURL, "/") + "/v1" // route LLM traffic through the guard proxy
	}
	r := &campaign.Runner{
		Scenario: sc, Harness: hc, Worlds: ws, WorldURL: worldURL,
		LLM:     harness.LLMSpec{BaseURL: llmBase, Model: c.llmModel, APIKey: c.llmKey},
		Offline: c.offline, GuardURL: c.guardURL, GuardMode: "off", MaxTurns: 12,
	}
	if sc.Sandbox {
		sink, err := world.NewSink()
		if err != nil {
			cleanup()
			return nil, err
		}
		hs, err := world.NewHostSecret()
		if err != nil {
			sink.Close()
			cleanup()
			return nil, err
		}
		prev := cleanup
		cleanup = func() { sink.Close(); hs.Close(); prev() }
		r.Sandbox, r.Sink, r.Host = &world.Sandbox{Bin: c.sandboxBin}, sink, hs
		fmt.Printf("sandbox: %s (canary sink on %s)\n", c.sandboxBin, sink.Addr)
	}
	if c.kernelURL != "" {
		r.Kernel = kernel.New(c.kernelURL)
		fmt.Printf("kernel bridge: emitting execute_tool spans to %s\n", c.kernelURL)
	}
	if c.offline {
		fmt.Println("NOTE: -offline uses a simulated gullible model. It validates the pipeline; it is not a measurement of any real model.")
	}
	return &env{r: r, sc: sc, seeds: seeds, traceDir: filepath.Join(c.outDir, "traces"), cleanup: cleanup}, nil
}

func writeReport(outDir, name string, v any) error {
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	p := filepath.Join(outDir, name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("report: %s\n", p)
	return nil
}

func cmdCampaign(args []string) error {
	fs := flag.NewFlagSet("campaign", flag.ExitOnError)
	c := addCommon(fs)
	guardMode := fs.String("guard", "off", "guard mode: off|monitor|enforce")
	regress := fs.Bool("regress", false, "also run the benign regression suite")
	_ = fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	e, err := c.setup(ctx, *guardMode != "off")
	if err != nil {
		return err
	}
	defer e.cleanup()
	if *guardMode != "off" {
		g := guard.New(c.guardURL)
		if err := g.Health(ctx); err != nil {
			return fmt.Errorf("guard not reachable at %s: %w", c.guardURL, err)
		}
		if err := g.PushPolicy(ctx, guard.PolicyFromScenario(e.sc, guard.AllDefenses)); err != nil {
			return err
		}
		if err := g.SetMode(ctx, *guardMode); err != nil {
			return err
		}
		e.r.GuardMode = *guardMode
	}
	fmt.Printf("== static permission audit (%s)\n", e.sc.ID)
	for _, f := range audit.Static(e.sc) {
		fmt.Printf("  [%s] %s %s: %s\n", strings.ToUpper(f.Severity), f.Kind, f.Tool, f.Detail)
	}
	fmt.Printf("== attack campaign: %d seeds × %d surfaces × %d repeats, guard=%s\n", len(e.seeds), len(e.sc.Surfaces), c.repeats, *guardMode)
	rep, _, err := e.r.Run(ctx, e.seeds, c.repeats, e.traceDir, os.Stdout)
	if err != nil {
		return err
	}
	fmt.Printf("\nASR %.0f%% (%d/%d)\n", rep.ASR*100, rep.Successes, rep.Attempts)
	for _, t := range rep.ByTechnique {
		fmt.Printf("  %-24s %d/%d  %.0f%%\n", t.Technique, t.Successes, t.Attempts, t.ASR*100)
	}
	out := map[string]any{"attack": rep}
	if *regress {
		fmt.Printf("\n== regression (benign tasks), guard=%s\n", *guardMode)
		rr, err := e.r.Regression(ctx, e.traceDir, os.Stdout)
		if err != nil {
			return err
		}
		fmt.Printf("\nutility %.0f%% (%d/%d)\n", rr.Utility*100, rr.Passed, rr.Tasks)
		out["regression"] = rr
	}
	fmt.Printf("traces: %s\n", e.traceDir)
	return writeReport(c.outDir, "report.json", out)
}

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	c := addCommon(fs)
	ablate := fs.Bool("ablate", true, "knock out one defense at a time")
	_ = fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	e, err := c.setup(ctx, true)
	if err != nil {
		return err
	}
	defer e.cleanup()
	g := guard.New(c.guardURL)
	if err := g.Health(ctx); err != nil {
		return fmt.Errorf("guard not reachable at %s: %w", c.guardURL, err)
	}
	v, err := e.r.Validate(ctx, g, e.seeds, c.repeats, *ablate, e.traceDir, os.Stdout)
	if err != nil {
		return err
	}
	fmt.Println("\n================ DEFENSE VALIDATION ================")
	fmt.Printf("exploits found (guard off):    %d/%d attempts  (ASR %.0f%%)\n", v.Baseline.Successes, v.Baseline.Attempts, v.Baseline.ASR*100)
	fmt.Printf("replayed under guard:          %d  ->  blocked %d (%.0f%%), residual ASR %.0f%%\n", v.Replayed, v.Blocked, v.BlockedPct*100, v.Defended.ASR*100)
	fmt.Printf("benign utility:                off %.0f%%  ->  on %.0f%%  (delta %+.0f pts)\n", v.RegressionOff.Utility*100, v.RegressionOn.Utility*100, v.UtilityDelta*100)
	if len(v.RegressionOn.Failed) > 0 {
		fmt.Printf("  benign tasks broken by guard: %v\n", v.RegressionOn.Failed)
	}
	if v.Guard != nil {
		fmt.Printf("guard decisions:               %v  by rule %v\n", v.Guard.Decisions, v.Guard.ByRule)
		fmt.Printf("guard decision latency:        p50 %dµs  p99 %dµs (n=%d)\n", v.Guard.Latency.P50, v.Guard.Latency.P99, v.Guard.Latency.N)
	}
	return writeReport(c.outDir, "validation.json", v)
}

func cmdHunt(args []string) error {
	fs := flag.NewFlagSet("hunt", flag.ExitOnError)
	c := addCommon(fs)
	budget := fs.Int("budget", 40, "bandit pulls (payload executions, excluding confirm/minimise re-runs)")
	reliab := fs.Int("reliability-runs", 3, "runs used to estimate a discovery's reliability")
	minRuns := fs.Int("minimize-runs", 12, "max extra runs to shrink a winning payload")
	stopAfter := fs.Int("stop-after", 0, "stop after N discoveries (0 = spend the whole budget)")
	llmRewrite := fs.Bool("llm-rewrite", true, "let the pi AttackerAgent write payloads (needs a real LLM)")
	vsDefense := fs.Bool("vs-defense", false, "after the unguarded hunt, hunt again against the enforcing guard")
	opsFlag := fs.String("ops", "", "comma list of mutation operators (default: all deterministic + llm_rewrite when a real LLM is used)")
	surfFlag := fs.String("surfaces", "", "comma list of surface ids to attack (default: all)")
	rngSeed := fs.Int64("rng-seed", 1, "search RNG seed (reproducible exploration order)")
	_ = fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	e, err := c.setup(ctx, *vsDefense)
	if err != nil {
		return err
	}
	defer e.cleanup()

	ops := append([]string{}, attacker.DeterministicOps...)
	useLLM := *llmRewrite && !c.offline
	if useLLM {
		ops = append(ops, attacker.OpLLMRewrite)
	}
	if *opsFlag != "" {
		ops = strings.Split(*opsFlag, ",")
		useLLM = false
		for _, o := range ops {
			if o == attacker.OpLLMRewrite {
				useLLM = !c.offline
			}
		}
	}
	var surfaces []string
	for _, sf := range e.sc.Surfaces {
		surfaces = append(surfaces, sf.ID)
	}
	if *surfFlag != "" {
		surfaces = strings.Split(*surfFlag, ",")
	}
	arms := attacker.BuildArms(e.seeds, surfaces, ops)
	var obj string
	for _, o := range e.sc.Objectives {
		obj += o.Description + "; "
	}
	var crafter attacker.Crafter
	if useLLM {
		crafter = &attacker.HarnessCrafter{R: e.r, Objective: obj, SurfaceKind: func(id string) string {
			if sf := e.sc.Surface(id); sf != nil {
				return sf.Kind
			}
			return "document"
		}}
	}
	cfg := attacker.Config{
		Budget: *budget, Reliab: *reliab, MinimizeMax: *minRuns, StopAfter: *stopAfter, Seed: *rngSeed,
		Vars: e.r.Vars(), Log: os.Stdout,
	}
	hunt := func(label string) (*attacker.Result, error) {
		fmt.Printf("== hunt (%s): %d arms, budget %d, llm_rewrite=%v\n", label, len(arms), *budget, useLLM)
		ex := &attacker.RunnerExecutor{R: e.r, OutDir: e.traceDir}
		return attacker.Hunt(ctx, ex, crafter, arms, cfg)
	}
	out := map[string]any{}
	var g *guard.Client
	if *vsDefense {
		g = guard.New(c.guardURL)
		if err := g.Health(ctx); err != nil {
			return fmt.Errorf("guard not reachable at %s: %w", c.guardURL, err)
		}
		if err := g.PushPolicy(ctx, guard.PolicyFromScenario(e.sc, guard.AllDefenses)); err != nil {
			return err
		}
		_ = g.SetMode(ctx, "off")
	}
	open, err := hunt("guard off")
	if err != nil {
		return err
	}
	printHunt(open)
	out["guard_off"] = open
	if *vsDefense {
		e.r.GuardMode = "enforce"
		if err := g.SetMode(ctx, "enforce"); err != nil {
			return err
		}
		def, err := hunt("guard enforce")
		if err != nil {
			return err
		}
		printHunt(def)
		out["guard_enforce"] = def
		fmt.Printf("\nadaptive attacker vs defense: %d discoveries unguarded -> %d against the guard (%d/%d attempts)\n",
			len(open.Discoveries), len(def.Discoveries), len(def.Discoveries), def.Attempts)
	}
	return writeReport(c.outDir, "hunt.json", out)
}

func printHunt(r *attacker.Result) {
	fmt.Printf("\n%d attempts, %d total executions, %d discoveries\n", r.Attempts, r.Executions, len(r.Discoveries))
	for _, d := range r.Discoveries {
		fmt.Printf("  * %s  reliability %.0f%% (%d runs)  found at attempt %d  trace %s\n    minimized payload: %q\n",
			d.Arm, d.Reliability*100, d.Runs, d.Attempt, d.TraceID, d.MinimizedPayload)
	}
	fmt.Println()
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address (keep it on loopback)")
	outDir := fs.String("out", "out", "directory holding traces/ and report JSON")
	scPath := fs.String("scenario", "scenarios/hr-records.yaml", "scenario file")
	seedsPath := fs.String("seeds", "seeds/seeds.yaml", "seed corpus for launched runs")
	sandboxBin := fs.String("sandbox", envOr("AGENTBREAK_SANDBOX", "guard/target/release/absandbox"), "absandbox binary for launched runs")
	guardURL := fs.String("guard-url", os.Getenv("AGENTBREAK_GUARD_URL"), "abguard-proxy base URL")
	offline := fs.Bool("offline", false, "launch runs with the simulated model by default")
	_ = fs.Parse(args)
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	srv := api.New(api.Config{OutDir: *outDir, ScenarioPath: *scPath, SeedsPath: *seedsPath, SandboxBin: *sandboxBin, GuardURL: *guardURL, Exe: exe, Offline: *offline})
	fmt.Printf("agentbreak API on http://%s (out=%s)\n", *addr, *outDir)
	return http.ListenAndServe(*addr, srv.Handler())
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	outDir := fs.String("out", "out", "directory with traces/")
	max := fs.Int("max", 5, "max advisories to write (one per technique, newest first)")
	llmURL := fs.String("llm-url", os.Getenv("AGENTBREAK_LLM_BASE_URL"), "OpenAI-compatible base URL")
	llmModel := fs.String("llm-model", os.Getenv("AGENTBREAK_LLM_MODEL"), "model id")
	llmKey := fs.String("llm-key", os.Getenv("AGENTBREAK_LLM_API_KEY"), "API key")
	_ = fs.Parse(args)
	if *llmURL == "" || *llmModel == "" {
		return fmt.Errorf("need -llm-url and -llm-model")
	}
	matches, _ := filepath.Glob(filepath.Join(*outDir, "traces", "*.json"))
	var traces []*trace.Trace
	for _, m := range matches {
		if tr, err := trace.Load(m); err == nil && tr.Kind == "attack" && tr.Success && tr.Attack != nil {
			traces = append(traces, tr)
		}
	}
	sort.Slice(traces, func(i, j int) bool { return traces[i].StartedAt.After(traces[j].StartedAt) })
	seen := map[string]bool{}
	c := llm.New(*llmURL, *llmModel, *llmKey)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var out []advisory.Advisory
	for _, tr := range traces {
		if seen[tr.Attack.Technique] || len(out) >= *max {
			continue
		}
		seen[tr.Attack.Technique] = true
		fmt.Printf("advisory for %s (%s)…\n", tr.TraceID, tr.Attack.Technique)
		a := advisory.Write(ctx, c, tr)
		if a.Error != "" {
			fmt.Println("  failed:", a.Error)
		} else {
			fmt.Println("  ", a.Title)
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		fmt.Println("no successful attack traces to explain")
	}
	return writeReport(*outDir, "advisories.json", out)
}
