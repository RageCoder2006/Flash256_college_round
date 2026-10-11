// avhsol: autonomous AI red-team control plane.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/41vi4p/avhsol/core/internal/home"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"net/http"

	"github.com/41vi4p/avhsol/core/internal/advisory"
	"github.com/41vi4p/avhsol/core/internal/api"
	"github.com/41vi4p/avhsol/core/internal/attacker"
	"github.com/41vi4p/avhsol/core/internal/audit"
	"github.com/41vi4p/avhsol/core/internal/brand"
	"github.com/41vi4p/avhsol/core/internal/campaign"
	"github.com/41vi4p/avhsol/core/internal/cliagent"
	"github.com/41vi4p/avhsol/core/internal/export"
	"github.com/41vi4p/avhsol/core/internal/graph"
	"github.com/41vi4p/avhsol/core/internal/guard"
	"github.com/41vi4p/avhsol/core/internal/harness"
	"github.com/41vi4p/avhsol/core/internal/kernel"
	"github.com/41vi4p/avhsol/core/internal/llm"
	"github.com/41vi4p/avhsol/core/internal/scenario"
	"github.com/41vi4p/avhsol/core/internal/sign"
	"github.com/41vi4p/avhsol/core/internal/trace"
	"github.com/41vi4p/avhsol/core/internal/world"
)

// legacyEnv lets existing setups keep working: AGENTBREAK_FOO is read as AVHSOL_FOO unless that is set.
func legacyEnv() {
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(k, "AGENTBREAK_") {
			if nk := "AVHSOL_" + strings.TrimPrefix(k, "AGENTBREAK_"); os.Getenv(nk) == "" {
				_ = os.Setenv(nk, v)
			}
		}
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, brand.Banner()+"\n"+brand.Credits()+"\n\n"+`usage: avhsol <command> [flags]

commands:
  <dir>      audit the AI agent whose code is in <dir> (try: avhsol .): reads the code, then attacks it in a sandbox and writes the report
  init       write a starter avhsol.yaml (how to launch your agent) into a codebase
  mcp        expose AVHSOL's tools to Claude Code or any MCP client over stdio (claude mcp add avhsol -- avhsol mcp)
  tui        interactive menus: pick a scenario, agent and options, then audit, attack, hunt or validate (also: run avhsol with no arguments)
  audit      static permission audit of a scenario
  campaign   run seed attacks (and optionally the benign regression suite)
  policy-test  replay recorded traces through a policy: what it would have stopped, what it would break
  intel      threat intel: sync GHSA/NVD/OSV/KEV/EPSS/research into a local cache, generate seeds, offline bundles
  summary    the security evaluation of a run directory: rating, success rates with intervals, control comparison, defenses
  fork       live revive: re-walk a recorded run and let the model take over at a chosen step (guard/edits optional)
  netfwd     (internal) port forwarder started inside gVisor containers
  scengen    generate a test scenario from an agent's tool list (JSON file or live MCP server)
  mcp-serve  run the poisoned MCP server used by mcp targets (stdio; started by the agent under test)
  graph      bitemporal trace graph (Neo4j) + vector store (Qdrant): init, ingest, stats, ask, ...
  report     LLM-written advisories for confirmed exploits (explanation only; verdicts stay deterministic)
  serve      dashboard API (traces, reports, guard control, launch runs)
  hunt       autonomous adaptive attack search (bandit + LLM payload crafting + minimisation)
  validate   baseline attacks -> replay under the Rust guard -> benign regression -> ablation
  export     write the security report: html, pdf, md, json or sarif (layout from a JSON skeleton)
  auditlog   verify | tail the API's tamper-evident audit log
  version    what this is, and who made it
  keygen     create the Ed25519 key that signs every trace
  verify     verify a saved trace: hash chain, and signature if a public key is available

run "avhsol <command> -h" for flags.`)
	os.Exit(2)
}

func main() {
	legacyEnv()
	if len(os.Args) < 2 {
		if isTerminal() { // no command given on a terminal: open the menu
			if err := cmdTUI(nil); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			return
		}
		usage()
	}
	var err error
	if dirArg(os.Args[1]) { // `avhsol .`: audit the agent code in this directory
		if err := cmdWhitebox(os.Args[1], os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "mcp":
		err = cmdMCP(os.Args[2:])
	case "audit":
		err = cmdAudit(os.Args[2:])
	case "campaign":
		err = cmdCampaign(os.Args[2:])
	case "policy-test":
		err = cmdPolicyTest(os.Args[2:])
	case "graph":
		err = cmdGraph(os.Args[2:])
	case "intel":
		err = cmdIntel(os.Args[2:])
	case "tui", "menu":
		err = cmdTUI(os.Args[2:])
	case "summary":
		err = cmdSummary(os.Args[2:])
	case "fork":
		err = cmdFork(os.Args[2:])
	case "netfwd":
		err = cmdNetFwd(os.Args[2:])
	case "scengen":
		err = cmdScengen(os.Args[2:])
	case "mcp-serve":
		err = cmdMCPServe(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "hunt":
		err = cmdHunt(os.Args[2:])
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "version", "about", "-v", "--version":
		fmt.Println(brand.Banner())
		fmt.Println(brand.Tagline)
		fmt.Printf("version %s\n%s\n", brand.Version, brand.Credits())
	case "export":
		err = cmdExport(os.Args[2:])
	case "auditlog":
		err = cmdAuditLog(os.Args[2:])
	case "keygen":
		err = cmdKeygen(os.Args[2:])
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
	sc, err := scenario.Load(home.Resolve(*scPath))
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

func signingKeyPath() string {
	return graph.Setting("AVHSOL_SIGNING_KEY", "", home.SigningKey())
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", signingKeyPath(), "where to write the private key (the public key goes next to it as .pub)")
	_ = fs.Parse(args)
	id, err := sign.Generate(*out)
	if err != nil {
		return err
	}
	fmt.Printf("signing key %s written to %s (mode 600); public key %s.pub\nkeep the private key off shared drives: whoever has it can mint traces that verify\n", id, *out, *out)
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubPath := fs.String("pub", signingKeyPath()+".pub", "public key to verify the signature against")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: avhsol verify [-pub key.pub] <trace.json>")
	}
	tr, err := trace.Load(fs.Arg(0))
	if err != nil {
		return err
	}
	if pub, perr := sign.LoadPublic(*pubPath); perr == nil {
		if err := sign.Verify(tr, pub); err != nil {
			return err
		}
		fmt.Printf("OK  %s  steps=%d  head=%s  signed by %s\n", tr.TraceID, len(tr.Steps), tr.HeadHash(), tr.Signature.KeyID)
		return nil
	}
	if err := tr.Verify(); err != nil {
		return err
	}
	fmt.Printf("OK (hash chain only: no public key at %s)  %s  steps=%d  head=%s\n", *pubPath, tr.TraceID, len(tr.Steps), tr.HeadHash())
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
	isolation                                                                string
	sandboxBin, kernelURL, thinking, targetPath                              string
	repeats                                                                  int
	offline, useGraph                                                        bool
}

func addCommon(fs *flag.FlagSet) *common {
	c := &common{}
	fs.StringVar(&c.scPath, "scenario", "scenarios/hr-records.yaml", "scenario file")
	fs.StringVar(&c.seedPath, "seeds", "seeds/seeds.yaml", "seed corpus")
	fs.StringVar(&c.outDir, "out", "out", "output directory for traces and report")
	fs.IntVar(&c.repeats, "repeats", 1, "runs per seed×surface")
	fs.BoolVar(&c.offline, "offline", false, "SIMULATED gullible model (pipeline test; not a security result)")
	fs.StringVar(&c.guardURL, "guard-url", os.Getenv("AVHSOL_GUARD_URL"), "avhsol-proxy base URL, e.g. http://127.0.0.1:7077")
	fs.StringVar(&c.harnessCmd, "harness", envOr("AVHSOL_HARNESS_CMD", defaultHarnessCmd()), "command that starts the TS harness")
	fs.StringVar(&c.llmURL, "llm-url", os.Getenv("AVHSOL_LLM_BASE_URL"), "OpenAI-compatible base URL (…/v1)")
	fs.StringVar(&c.llmModel, "llm-model", os.Getenv("AVHSOL_LLM_MODEL"), "model id")
	fs.StringVar(&c.sandboxBin, "sandbox", envOr("AVHSOL_SANDBOX", home.Bin("avhsol-sandbox")), "avhsol-sandbox binary (used when the scenario has sandbox: true)")
	fs.StringVar(&c.kernelURL, "kernel-otlp", os.Getenv("AVHSOL_KERNEL_OTLP"), "TRIVEKTRA OTLP receiver (e.g. http://127.0.0.1:4318): emit a span per sandboxed tool call")
	fs.StringVar(&c.thinking, "target-thinking", "default", "target model chain-of-thought: default|off (off is faster; changes the target's behaviour)")
	fs.StringVar(&c.isolation, "isolation", "", "how a -target agent is confined: landlock (default) or gvisor (Docker + runsc); overrides the target file")
	fs.StringVar(&c.targetPath, "target", "", "CLI coding-agent target (targets/*.yaml); default: the pi harness with simulated tools")
	fs.BoolVar(&c.useGraph, "graph", os.Getenv("AVHSOL_GRAPH") == "1", "write every trace into the Neo4j/Qdrant trace graph as it is produced (needs scripts/stack.sh up)")
	fs.StringVar(&c.llmKey, "llm-key", os.Getenv("AVHSOL_LLM_API_KEY"), "API key (if any)")
	return c
}

type env struct {
	finishGraph func()
	r           *campaign.Runner
	sc          *scenario.Scenario
	seeds       []campaign.Seed
	traceDir    string
	cleanup     func()
}

func (c *common) setup(ctx context.Context, needGuard bool) (*env, error) {
	c.scPath, c.seedPath, c.targetPath = home.Resolve(c.scPath), home.Resolve(c.seedPath), home.Resolve(c.targetPath)
	httpTarget := false // a black-box HTTP agent brings its own model: AVHSOL needs none to drive it
	if c.targetPath != "" {
		if t, err := cliagent.Load(c.targetPath); err == nil && t.Kind == "http" {
			httpTarget = true
		}
	}
	if !c.offline && !httpTarget && (c.llmURL == "" || c.llmModel == "") {
		return nil, fmt.Errorf("need -llm-url and -llm-model (or AVHSOL_LLM_BASE_URL / AVHSOL_LLM_MODEL), or pass -offline")
	}
	if needGuard && c.guardURL == "" {
		return nil, fmt.Errorf("this command needs -guard-url (start the Rust guard: cargo run -p avhsol-proxy)")
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
	var hc *harness.Client
	cleanup := func() { ws.Close() }
	// A CLI/HTTP target brings its own tools: the pi harness (Node) is only needed for simulated-tool scenarios and LLM payload writing.
	if c.targetPath != "" && !harnessPresent(c.harnessCmd) {
		fmt.Println("harness: not installed (not needed for a -target agent; simulated-tool scenarios and LLM payload writing need it)")
	} else {
		hc, err = harness.Start(strings.Fields(c.harnessCmd))
		if err != nil {
			ws.Close()
			return nil, err
		}
		cleanup = func() { hc.Close(); ws.Close() }
		pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := hc.Ping(pctx); err != nil {
			cleanup()
			return nil, fmt.Errorf("harness not responding: %w", err)
		}
	}
	llmBase := c.llmURL
	if c.guardURL != "" && !c.offline {
		llmBase = strings.TrimRight(c.guardURL, "/") + "/v1" // route LLM traffic through the guard proxy
	}
	r := &campaign.Runner{
		Scenario: sc, Harness: hc, Worlds: ws, WorldURL: worldURL,
		LLM:     harness.LLMSpec{BaseURL: llmBase, Model: c.llmModel, APIKey: c.llmKey, Thinking: c.thinking},
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
	if c.targetPath != "" {
		if !sc.Sandbox || r.Sandbox == nil {
			cleanup()
			return nil, fmt.Errorf("-target needs a sandbox scenario (sandbox: true)")
		}
		t, err := cliagent.Load(c.targetPath)
		if err != nil {
			cleanup()
			return nil, err
		}
		if t.Kind != "http" && c.guardURL == "" {
			cleanup()
			return nil, fmt.Errorf("-target needs -guard-url: the guard proxy is the agent's only route to the model")
		}
		if c.isolation != "" {
			if c.isolation != cliagent.IsolationLandlock && c.isolation != cliagent.IsolationGVisor {
				cleanup()
				return nil, fmt.Errorf("-isolation must be landlock or gvisor")
			}
			t.Isolation = c.isolation
		}
		if t.Isolation == cliagent.IsolationGVisor {
			if err := cliagent.GVisorAvailable(ctx); err != nil {
				cleanup()
				return nil, err
			}
		}
		r.CLI, r.CLIVars = t, cliVars(c)
		r.CLIVars["sink_url"] = r.Sink.URL()
		switch t.Kind {
		case "http":
			fmt.Printf("target: HTTP agent %q at %s (black box: tool calls are not observed, no guard in the path)\n", t.Name, t.HTTP.URL)
		case "mcp":
			fmt.Printf("target: CLI agent %q with a poisoned MCP server (sandboxed, %s wire via %s)\n", t.Name, t.Wire, c.guardURL)
		default:
			fmt.Printf("target: CLI agent %q (sandboxed, %s wire via %s)\n", t.Name, t.Wire, c.guardURL)
		}
	}
	if c.kernelURL != "" {
		r.Kernel = kernel.New(c.kernelURL)
		fmt.Printf("kernel bridge: emitting execute_tool spans to %s\n", c.kernelURL)
	}
	if sg, err := sign.LoadSigner(signingKeyPath()); err == nil {
		r.Sign = sg.Sign
		fmt.Printf("signing: every trace is signed with key %s\n", sg.ID)
	} else if os.Getenv("AVHSOL_REQUIRE_SIGNING") == "1" {
		cleanup()
		return nil, fmt.Errorf("signing is required but no key at %s: run `avhsol keygen`", signingKeyPath())
	} else {
		fmt.Println("signing: OFF (no key; run `avhsol keygen` so traces are tamper-evident beyond the hash chain)")
	}
	finish := func() {}
	if c.useGraph {
		gs, err := graph.Open(ctx, graph.LoadConfig())
		if err != nil {
			cleanup()
			return nil, err
		}
		if err := gs.EnsureSchema(ctx); err != nil {
			cleanup()
			return nil, err
		}
		ix := graph.LoadIndex()
		ingested, failed := 0, 0
		r.OnTrace = func(tr *trace.Trace) {
			if _, err := gs.IngestTrace(ctx, tr, sc, ix); err != nil {
				failed++
				fmt.Fprintf(os.Stderr, "  graph: %s: %v\n", tr.TraceID, err)
				return
			}
			ingested++
		}
		finish = func() {
			if err := gs.Relink(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "  graph: linking replays:", err)
			}
			fmt.Printf("graph: %d traces written (%d failed), vectors %s\n", ingested, failed, ix.Emb.Name())
			gs.Close(ctx)
		}
		fmt.Printf("graph: recording every trace to Neo4j (%s) and Qdrant\n", graph.LoadConfig().URI)
	}
	if c.offline {
		fmt.Println("NOTE: -offline uses a simulated gullible model. It validates the pipeline; it is not a measurement of any real model.")
	}
	return &env{r: r, sc: sc, seeds: seeds, traceDir: filepath.Join(c.outDir, "traces"), cleanup: cleanup, finishGraph: finish}, nil
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
	printEvaluation(outDir)
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
	defer e.finishGraph()
	if *guardMode != "off" {
		g := guard.New(c.guardURL)
		if err := g.Health(ctx); err != nil {
			return fmt.Errorf("guard not reachable at %s: %w", c.guardURL, err)
		}
		if err := g.PushPolicy(ctx, e.r.Policy(guard.AllDefenses)); err != nil {
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
	fmt.Printf("\nASR %.0f%% (%d/%d valid runs)", rep.ASR*100, rep.Successes, rep.Valid)
	if rep.Errors > 0 {
		fmt.Printf("  [%d runs errored and are excluded]", rep.Errors)
	}
	fmt.Println()
	for _, o := range rep.ByObjective {
		fmt.Printf("  objective %-30s %-9s %d/%d  %.0f%%\n", o.Objective, o.Severity, o.Successes, o.Valid, o.Rate*100)
	}
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
	for i, a := range args { // validate replays attacks through the guard proxy, which a black-box HTTP agent never touches
		if (a == "-target" || a == "--target") && i+1 < len(args) {
			if t, err := cliagent.Load(args[i+1]); err == nil && t.Kind == "http" {
				return fmt.Errorf("validate needs the guard in the agent's model path, which a black-box HTTP target does not allow; use campaign or hunt for HTTP targets")
			}
		}
	}
	c := addCommon(fs)
	ablate := fs.Bool("ablate", true, "knock out one defense at a time")
	replayFrom := fs.String("replay-from", "", "reuse guard-off attack traces from this out dir instead of re-running the attack phase")
	_ = fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	e, err := c.setup(ctx, true)
	if err != nil {
		return err
	}
	defer e.cleanup()
	defer e.finishGraph()
	g := guard.New(c.guardURL)
	if err := g.Health(ctx); err != nil {
		return fmt.Errorf("guard not reachable at %s: %w", c.guardURL, err)
	}
	var prior []*trace.Trace
	if *replayFrom != "" {
		ms, _ := filepath.Glob(filepath.Join(*replayFrom, "traces", "*.json"))
		for _, m := range ms {
			if tr, err := trace.Load(m); err == nil && tr.Kind == "attack" && tr.Attack != nil && tr.GuardMode == "off" {
				prior = append(prior, tr)
			}
		}
		if len(prior) == 0 {
			return fmt.Errorf("no guard-off attack traces in %s", *replayFrom)
		}
	}
	v, err := e.r.Validate(ctx, g, e.seeds, c.repeats, *ablate, e.traceDir, os.Stdout, prior)
	if err != nil {
		return err
	}
	fmt.Println("\n================ DEFENSE VALIDATION ================")
	den := v.Baseline.Valid
	if den == 0 {
		den = v.Baseline.Attempts
	}
	fmt.Printf("exploits found (guard off):    %d/%d valid runs  (ASR %.0f%%)", v.Baseline.Successes, den, v.Baseline.ASR*100)
	if v.Baseline.Errors > 0 {
		fmt.Printf("  [%d errored runs excluded]", v.Baseline.Errors)
	}
	fmt.Println()
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
	defer e.finishGraph()

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
		if err := g.PushPolicy(ctx, e.r.Policy(guard.AllDefenses)); err != nil {
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
	addr := fs.String("addr", "127.0.0.1:8787", "listen address")
	outDir := fs.String("out", "out", "directory holding traces/ and report JSON")
	scPath := fs.String("scenario", "scenarios/hr-records.yaml", "scenario file")
	seedsPath := fs.String("seeds", "seeds/seeds.yaml", "seed corpus for launched runs")
	sandboxBin := fs.String("sandbox", envOr("AVHSOL_SANDBOX", home.Bin("avhsol-sandbox")), "avhsol-sandbox binary for launched runs")
	guardURL := fs.String("guard-url", os.Getenv("AVHSOL_GUARD_URL"), "avhsol-proxy base URL")
	offline := fs.Bool("offline", false, "launch runs with the simulated model by default")
	useGraph := fs.Bool("graph", os.Getenv("AVHSOL_GRAPH") == "1", "serve the trace graph (Neo4j + Qdrant)")
	noAuth := fs.Bool("no-auth", false, "DEVELOPMENT ONLY: skip authentication (loopback only)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate (enables HTTPS)")
	tlsKey := fs.String("tls-key", "", "TLS private key")
	allowRemote := fs.Bool("allow-remote", false, "allow listening on a non-loopback address (requires TLS and tokens)")
	_ = fs.Parse(args)

	*scPath, *seedsPath = home.Resolve(*scPath), home.Resolve(*seedsPath)
	host, _, _ := net.SplitHostPort(*addr)
	loopback := host == "127.0.0.1" || host == "::1" || host == "localhost"
	if !loopback && !*allowRemote {
		return fmt.Errorf("refusing to listen on %s: this API controls agent runs; bind to 127.0.0.1, or pass -allow-remote with TLS and tokens", *addr)
	}
	if !loopback && (*tlsCert == "" || *noAuth) {
		return fmt.Errorf("a non-loopback listener needs -tls-cert/-tls-key and must not use -no-auth")
	}
	auth := api.LoadAuth()
	switch {
	case *noAuth:
		if !loopback {
			return fmt.Errorf("-no-auth is only allowed on loopback")
		}
		auth.Open = true
		fmt.Fprintln(os.Stderr, "WARNING: authentication is OFF (development mode). Anything on this machine can start runs and read traces.")
	case !auth.Configured():
		return fmt.Errorf("no API tokens configured: run scripts/stack.sh up (generates them in deploy/stack/.env) or set AVHSOL_TOKEN_ADMIN etc.; use -no-auth only for local development")
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	auditPath := filepath.Join(*outDir, "audit.jsonl")
	alog, err := api.OpenAuditLog(auditPath)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cfg := api.Config{OutDir: *outDir, ScenarioPath: *scPath, SeedsPath: *seedsPath, SandboxBin: *sandboxBin, GuardURL: *guardURL,
		Exe: exe, Offline: *offline, Auth: auth, Audit: alog, AuditPath: auditPath}
	if *useGraph {
		ctx := context.Background()
		gs, err := graph.Open(ctx, graph.LoadConfig())
		if err != nil {
			return err
		}
		if err := gs.EnsureSchema(ctx); err != nil {
			return err
		}
		cfg.Graph, cfg.Index = gs, graph.LoadIndex()
		if u, m := os.Getenv("AVHSOL_LLM_BASE_URL"), os.Getenv("AVHSOL_LLM_MODEL"); u != "" && m != "" {
			cfg.LLM = llm.New(u, m, os.Getenv("AVHSOL_LLM_API_KEY"))
		}
	}
	srv := &http.Server{
		Addr: *addr, Handler: api.New(cfg).Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10,
	}
	scheme := "http"
	if *tlsCert != "" {
		scheme = "https"
	}
	fmt.Printf("%s API on %s://%s (out=%s, auth=%v, graph=%v, audit log %s)\n", brand.Name, scheme, *addr, *outDir, !auth.Open, cfg.Graph != nil, auditPath)
	if *tlsCert != "" {
		return srv.ListenAndServeTLS(*tlsCert, *tlsKey)
	}
	return srv.ListenAndServe()
}

// cliVars are the placeholders a CLI target definition can use.
func cliVars(c *common) cliagent.Vars {
	v := cliagent.Vars{"proxy_url": strings.TrimRight(c.guardURL, "/"), "api_key": c.llmKey, "model": c.llmModel}
	if exe, err := os.Executable(); err == nil {
		v["avhsol_bin"] = exe
		v["avhsol_dir"] = filepath.Dir(exe)
	}
	if cwd, err := os.Getwd(); err == nil {
		v["cwd"] = cwd
		v["pi_dir"] = filepath.Join(cwd, "pi")
		if d := os.Getenv("AVHSOL_AGENT_DIR"); d != "" {
			v["pi_dir"] = d
			v["agent_dir"] = d
		}
	}
	if p, err := exec.LookPath("node"); err == nil {
		if rp, err := filepath.EvalSymlinks(p); err == nil {
			v["node_dir"] = filepath.Dir(filepath.Dir(rp))
		}
	}
	return v
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	outDir := fs.String("out", "out", "directory with traces/")
	max := fs.Int("max", 5, "max advisories to write (one per technique, newest first)")
	llmURL := fs.String("llm-url", os.Getenv("AVHSOL_LLM_BASE_URL"), "OpenAI-compatible base URL")
	llmModel := fs.String("llm-model", os.Getenv("AVHSOL_LLM_MODEL"), "model id")
	llmKey := fs.String("llm-key", os.Getenv("AVHSOL_LLM_API_KEY"), "API key")
	_ = fs.Parse(args)
	if *llmURL == "" || *llmModel == "" {
		return fmt.Errorf("need -llm-url and -llm-model")
	}
	matches, _ := filepath.Glob(filepath.Join(*outDir, "traces", "*.json"))
	var traces []*trace.Trace
	for _, m := range matches {
		if tr, err := trace.Load(m); err == nil && tr.Kind == "attack" && campaign.SeverityWinner(tr) && tr.Attack != nil && tr.GuardMode == "off" {
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
		fmt.Println("no critical-severity attack traces to explain")
	}
	return writeReport(*outDir, "advisories.json", out)
}

func cmdAuditLog(args []string) error {
	fs := flag.NewFlagSet("auditlog", flag.ExitOnError)
	path := fs.String("file", "out/audit.jsonl", "audit log file")
	n := fs.Int("n", 20, "entries to show for tail")
	if len(args) < 1 {
		return fmt.Errorf("usage: avhsol auditlog verify|tail [-file out/audit.jsonl]")
	}
	_ = fs.Parse(args[1:])
	switch args[0] {
	case "verify":
		c, err := api.VerifyAuditLog(*path)
		if err != nil {
			return err
		}
		fmt.Printf("OK  %d entries, hash chain intact\n", c)
		return nil
	case "tail":
		es, err := api.TailAuditLog(*path, *n)
		if err != nil {
			return err
		}
		for _, e := range es {
			fmt.Printf("%s  %-8s %-5s %-28s %d %s\n", time.UnixMilli(e.TS).UTC().Format("15:04:05"), e.Role, e.Method, e.Path, e.Status, e.Note)
		}
		return nil
	}
	return fmt.Errorf("usage: avhsol auditlog verify|tail")
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	in := fs.String("in", "out", "run directory (traces/, validation.json, advisories.json)")
	format := fs.String("format", "html", "html | pdf | md | json | sarif")
	skeleton := fs.String("skeleton", "security-report", "built-in skeleton name or a path to your own JSON skeleton")
	outFile := fs.String("o", "", "output file (default: <in>/report.<ext>)")
	scenarios := fs.String("scenarios", "scenarios", "scenario directory (for scope and the permission audit)")
	scID := fs.String("scenario", "", "scenario id to report on (default: the one with the most attack runs)")
	title := fs.String("title", "", "report title")
	class := fs.String("classification", "", "classification on the cover (default CONFIDENTIAL)")
	list := fs.Bool("list-skeletons", false, "list the built-in skeletons")
	dump := fs.String("dump-skeleton", "", "print a built-in skeleton so you can copy and edit it")
	_ = fs.Parse(args)
	if *list {
		fmt.Println(strings.Join(export.BuiltinSkeletons(), "\n"))
		return nil
	}
	if *dump != "" {
		b, err := export.BuiltinSkeletonJSON(*dump)
		if err != nil {
			return fmt.Errorf("no built-in skeleton %q (have: %s)", *dump, strings.Join(export.BuiltinSkeletons(), ", "))
		}
		fmt.Print(string(b))
		return nil
	}
	o := export.Options{Dir: *in, ScenarioDir: home.Resolve(*scenarios), Scenario: *scID, Title: *title, Classification: *class}
	if pub, err := sign.LoadPublic(signingKeyPath() + ".pub"); err == nil {
		o.Pub = pub
	}
	if sg, err := sign.LoadSigner(signingKeyPath()); err == nil {
		o.Signer = sg
	}
	body, _, err := export.Generate(o, *skeleton, *format)
	if err != nil {
		return err
	}
	path := *outFile
	if path == "" {
		path = filepath.Join(*in, "report."+map[string]string{"html": "html", "pdf": "pdf", "md": "md", "json": "json", "sarif": "sarif"}[*format])
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes, %s, skeleton %s)\n", path, len(body), *format, *skeleton)
	return nil
}

// harnessPresent reports whether the harness script named in the command exists.
func harnessPresent(cmd string) bool {
	f := strings.Fields(cmd)
	if len(f) < 2 {
		return len(f) == 1
	}
	_, err := os.Stat(f[len(f)-1])
	return err == nil
}

// defaultHarnessCmd starts the pi harness from a checkout or an install that bundled it (scripts/install.sh --with-harness).
func defaultHarnessCmd() string {
	if d := home.HarnessDir(); d != "" {
		return "node " + filepath.Join(d, "packages", "avhsol", "src", "rpc.ts")
	}
	return "node pi/packages/avhsol/src/rpc.ts"
}
