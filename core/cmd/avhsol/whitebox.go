package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/41vi4p/avhsol/core/internal/api"
	"github.com/41vi4p/avhsol/core/internal/audit"
	"github.com/41vi4p/avhsol/core/internal/campaign"
	"github.com/41vi4p/avhsol/core/internal/eval"
	"github.com/41vi4p/avhsol/core/internal/export"
	"github.com/41vi4p/avhsol/core/internal/graph"
	"github.com/41vi4p/avhsol/core/internal/home"
	"github.com/41vi4p/avhsol/core/internal/runtime"
	"github.com/41vi4p/avhsol/core/internal/sign"
	"github.com/41vi4p/avhsol/core/internal/whitebox"
	"gopkg.in/yaml.v3"
)

// knownCommands are the words that are commands, so a directory with the same name never shadows one.
var knownCommands = map[string]bool{
	"tui": true, "menu": true, "audit": true, "campaign": true, "policy-test": true, "intel": true, "summary": true, "fork": true, "netfwd": true,
	"scengen": true, "mcp-serve": true, "graph": true, "report": true, "serve": true, "hunt": true, "validate": true, "export": true,
	"auditlog": true, "version": true, "about": true, "keygen": true, "verify": true, "init": true, "mcp": true,
}

// dirArg reports whether the first argument names a directory to audit (`avhsol .`, `avhsol ./agent`, `avhsol /path`).
func dirArg(a string) bool {
	if a == "" || strings.HasPrefix(a, "-") || (knownCommands[a] && !strings.ContainsAny(a, "./")) {
		return false
	}
	st, err := os.Stat(a)
	return err == nil && st.IsDir()
}

type step struct {
	name   string
	status string // pending | running | done | skipped | failed
	note   string
}

type checklist struct{ steps []*step }

func (c *checklist) add(name string) *step {
	s := &step{name: name, status: "pending"}
	c.steps = append(c.steps, s)
	return s
}

func (c *checklist) print() {
	fmt.Println("\naudit plan:")
	for i, s := range c.steps {
		fmt.Printf("  %d. %s\n", i+1, s.name)
	}
	fmt.Println()
}

func (s *step) skip(why string) { s.status, s.note = "skipped", why }

func (c *checklist) summary() {
	mark := map[string]string{"done": "✓", "skipped": "–", "failed": "✗", "pending": "·", "running": "…"}
	fmt.Println("\naudit steps:")
	for i, s := range c.steps {
		n := ""
		if s.note != "" {
			n = "  (" + s.note + ")"
		}
		fmt.Printf("  %s %d. %s%s\n", mark[s.status], i+1, s.name, n)
	}
}

func cmdWhitebox(dir string, args []string) error {
	fs := flag.NewFlagSet("avhsol <dir>", flag.ExitOnError)
	static := fs.Bool("static", false, "read the code only: no agent is launched")
	quick := fs.Bool("quick", false, "1 repeat, no per-defense ablation (the result gets no risk rating)")
	online := fs.Bool("online", false, "check exact dependency versions against OSV (sends package names and versions to osv.dev)")
	repeats := fs.Int("repeats", 3, "runs per seed and surface (3 is the minimum for a risk rating)")
	skip := fs.String("skip", "", "comma list: ablation")
	isolation := fs.String("isolation", "", "landlock (default) or gvisor")
	outDir := fs.String("out", "", "run directory (default: a new directory under the AVHSOL state directory, never inside the audited code)")
	asJSON := fs.Bool("json", false, "print the static report as JSON and stop")
	sarif := fs.String("sarif", "", "also write the static findings as SARIF to this file")
	noBuild := fs.Bool("no-build", false, "never run the agent's build command")
	guardURL := fs.String("guard-url", os.Getenv("AVHSOL_GUARD_URL"), "use this running avhsol-proxy instead of starting one")
	llmURL := fs.String("llm-url", os.Getenv("AVHSOL_LLM_BASE_URL"), "OpenAI-compatible base URL (…/v1)")
	llmModel := fs.String("llm-model", os.Getenv("AVHSOL_LLM_MODEL"), "model id")
	useGraph := fs.Bool("graph", os.Getenv("AVHSOL_GRAPH") == "1", "record every trace in the Neo4j/Qdrant graph")
	_ = fs.Parse(args)
	llmKey := os.Getenv("AVHSOL_LLM_API_KEY") // environment only

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	fmt.Println("AVHSOL whitebox audit of", abs)
	res, err := whitebox.Scan(ctx, whitebox.Options{Dir: abs, Online: *online})
	if err != nil {
		return err
	}
	rd := *outDir
	if rd == "" {
		rd = filepath.Join(home.StateDir(), "runs", home.Slug(res.Report.Name)+"-"+time.Now().Format("20060102-150405"))
	}
	if rel, err := filepath.Rel(abs, mustAbs(rd)); err == nil && !strings.HasPrefix(rel, "..") {
		return fmt.Errorf("the run directory %s is inside the audited code; the audit never writes there (pick another -out)", rd)
	}
	if *asJSON {
		b, _ := json.MarshalIndent(res.Report, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	plan := &checklist{}
	sStatic := plan.add("Read the code: framework, tools, risky patterns, dependencies")
	sPerm := plan.add("Static permission audit of the generated test scenario")
	sBuild := plan.add("Make sure the agent is built")
	sProxy := plan.add("Start the guard proxy (the agent's only route to the model)")
	sAttack := plan.add("Attack campaign (guard off): seeds × surfaces × repeats, with a no-attack control")
	sGuard := plan.add("Defense validation: replay exploits under the guard (enforce)")
	sBenign := plan.add("Benign-task regression: what the guard costs")
	sAblate := plan.add("Per-defense ablation (D1–D7)")
	sMulti := plan.add("Multi-stage attacks (poison now, trigger in a later session)")
	sEval := plan.add("Evaluation: success rates with intervals, comparison with the control")
	sReport := plan.add("Reports: HTML, JSON, SARIF")
	plan.print()

	res.Report.Print(os.Stdout)
	if err := res.WriteFiles(rd); err != nil {
		return err
	}
	if *sarif != "" {
		if err := os.WriteFile(*sarif, res.Report.SARIF(), 0o644); err != nil {
			return err
		}
	}
	sStatic.status = "done"
	fmt.Printf("\n== static permission audit (%s, generated from the tools above)\n", res.Scenario.ID)
	for _, f := range audit.Static(res.Scenario) {
		fmt.Printf("  [%s] %s %s: %s\n", strings.ToUpper(f.Severity), f.Kind, f.Tool, f.Detail)
	}
	sPerm.status = "done"
	fmt.Printf("\nrun directory: %s\n", rd)

	stopHere := func(why string) error {
		for _, s := range []*step{sBuild, sProxy, sAttack, sGuard, sBenign, sAblate, sMulti, sEval, sReport} {
			if s.status == "pending" {
				s.skip(why)
			}
		}
		plan.summary()
		fmt.Printf("\nstatic report: %s\n", filepath.Join(rd, "whitebox.json"))
		return nil
	}
	if *static {
		return stopHere("--static")
	}
	prof := res.Profile
	if prof == nil {
		fmt.Println("\nThe dynamic attack needs to know how to launch this agent, and it was not recognised.")
		fmt.Println("Add an avhsol.yaml next to the code (run `avhsol init` to write a starter), for example:")
		fmt.Println("  name: my-agent\n  run: [python, agent.py, \"{task}\"]\n  model_env: openai      # which base-URL variables point at the guard")
		return stopHere("agent not recognised: no avhsol.yaml")
	}
	if prof.Target == nil {
		fmt.Printf("\nCannot launch %s: %s\n", prof.Name, prof.Missing)
		return stopHere("cannot launch: " + prof.Missing)
	}
	if *llmURL == "" || *llmModel == "" {
		fmt.Println("\nNo model is configured, so no agent is launched (a simulated model would not measure this agent).")
		fmt.Println("Set AVHSOL_LLM_BASE_URL, AVHSOL_LLM_MODEL and AVHSOL_LLM_API_KEY, then run avhsol again. The static report above is complete.")
		return stopHere("no model configured")
	}
	sandbox := home.Bin("avhsol-sandbox")
	if _, err := os.Stat(sandbox); err != nil {
		fmt.Printf("\nThe sandbox binary is missing (%s). Build it (cargo build --release in guard/) or run scripts/install.sh.\n", sandbox)
		return stopHere("avhsol-sandbox missing")
	}

	// build the agent when needed: this runs the repository's own scripts, outside the sandbox, so say so first
	if prof.Missing != "" && len(prof.BuildCmd) > 0 {
		if *noBuild {
			fmt.Printf("\n%s and --no-build was given.\n", prof.Missing)
			return stopHere(prof.Missing)
		}
		fmt.Printf("\n== build: %s\n   running `%s` in %s (this executes the agent's own build scripts, outside the sandbox; pass --no-build to refuse)\n", prof.Missing, strings.Join(prof.BuildCmd, " "), abs)
		cmd := exec.CommandContext(ctx, prof.BuildCmd[0], prof.BuildCmd[1:]...)
		cmd.Dir, cmd.Stdout, cmd.Stderr = abs, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			sBuild.status, sBuild.note = "failed", err.Error()
			return stopHere("build failed")
		}
		if again := whitebox.DetectProfile(abs, res.Config); again != nil && again.Missing != "" {
			fmt.Printf("still not runnable: %s\n", again.Missing)
			return stopHere(again.Missing)
		}
	} else if prof.Missing != "" {
		fmt.Printf("\nCannot launch %s: %s\n", prof.Name, prof.Missing)
		return stopHere(prof.Missing)
	}
	sBuild.status = "done"

	// the proxy holds the real key; the agent only ever sees a placeholder
	px, err := runtime.EnsureProxy(ctx, runtime.Options{Existing: *guardURL, Upstream: *llmURL, Model: *llmModel, APIKey: llmKey})
	if err != nil {
		sProxy.status, sProxy.note = "failed", err.Error()
		fmt.Println("\nerror:", err)
		return stopHere("guard proxy unavailable")
	}
	defer px.Stop()
	agentKey := "avhsol-placeholder"
	if !px.Started {
		agentKey = llmKey // a proxy someone else started does not hold our key
	}
	sProxy.status, sProxy.note = "done", px.URL
	fmt.Printf("\nguard proxy: %s (started by this run: %v)\n", px.URL, px.Started)

	// launch definition and seeds, recorded in the run directory
	if err := prof.WriteTarget(filepath.Join(rd, "target.yaml")); err != nil {
		return err
	}
	seedsPath, nSeeds, err := writeSeeds(rd)
	if err != nil {
		return err
	}
	_ = os.Setenv("AVHSOL_AGENT_DIR", abs)
	reps := *repeats
	ablate := !strings.Contains(*skip, "ablation")
	if *quick {
		reps, ablate = 1, false
	}
	if reps < 3 {
		fmt.Println("note: fewer than 3 repeats: the result gets no risk rating")
	}
	if !ablate {
		sAblate.skip("skipped by request")
	}
	evalScenarioOverride = filepath.Join(rd, "scenarios")
	dyn := filepath.Join(rd, "dyn")
	vargs := []string{
		"-scenario", filepath.Join(rd, "scenarios", res.Scenario.ID+".yaml"), "-seeds", seedsPath, "-target", filepath.Join(rd, "target.yaml"),
		"-guard-url", px.URL, "-out", dyn, "-repeats", fmt.Sprint(reps), "-llm-url", *llmURL, "-llm-model", *llmModel, "-llm-key", agentKey,
		"-sandbox", sandbox, fmt.Sprintf("-ablate=%v", ablate),
	}
	if *isolation != "" {
		vargs = append(vargs, "-isolation", *isolation)
	}
	graphSet := false
	fs.Visit(func(f *flag.Flag) { graphSet = graphSet || f.Name == "graph" })
	if !graphSet && os.Getenv("AVHSOL_GRAPH") != "0" && graphReachable(ctx) {
		*useGraph = true // the stack is up: record the run so the graph page shows it too
		fmt.Println("graph: Neo4j is reachable, recording this run in the graph (AVHSOL_GRAPH=0 to skip)")
	}
	if *useGraph {
		vargs = append(vargs, "-graph")
	}
	fmt.Printf("\n== dynamic audit: %d seeds (incl. controls) × %d surfaces × %d repeats, agent %q\n", nSeeds, len(res.Scenario.Surfaces), reps, prof.Name)
	sAttack.status, sGuard.status, sBenign.status = "running", "running", "running"
	if ablate {
		sAblate.status = "running"
	}
	verr := cmdValidate(vargs)
	if ctx.Err() != nil {
		fmt.Println("\ninterrupted: partial results are kept in", dyn)
		for _, s := range []*step{sAttack, sGuard, sBenign, sAblate} {
			if s.status == "running" {
				s.status, s.note = "failed", "interrupted"
			}
		}
		return stopHere("interrupted")
	}
	if verr != nil {
		for _, s := range []*step{sAttack, sGuard, sBenign, sAblate} {
			if s.status == "running" {
				s.status, s.note = "failed", verr.Error()
			}
		}
		fmt.Println("\nerror:", verr)
		return stopHere("dynamic audit failed")
	}
	for _, s := range []*step{sAttack, sGuard, sBenign, sAblate} {
		if s.status == "running" {
			s.status = "done"
		}
	}
	sMulti.skip("needs an agent with persistent memory and a fresh-session follow-up; not available for launched CLI agents yet")

	// evaluation and reports
	var rating string
	if e, err := buildEvaluation(dyn, evalScenarioDir(), res.Scenario.ID); err == nil {
		_ = os.WriteFile(filepath.Join(rd, "evaluation.txt"), []byte(eval.Text(e)), 0o644)
		jb, _ := json.MarshalIndent(e, "", "  ")
		_ = os.WriteFile(filepath.Join(rd, "evaluation.json"), jb, 0o644)
		rating = e.Rating
		if reps < 3 {
			rating = "no rating (fewer than 3 repeats)"
		}
		sEval.status = "done"
	} else {
		sEval.status, sEval.note = "failed", err.Error()
	}
	reportOK := true
	formats := []string{"html", "sarif", "json"}
	if export.PDFAvailable() {
		formats = append(formats, "pdf")
	}
	eo := export.Options{Dir: dyn, ScenarioDir: filepath.Join(rd, "scenarios"), Scenario: res.Scenario.ID, Title: "AVHSOL audit: " + res.Report.Name, Classification: "CONFIDENTIAL"}
	if pub, err := sign.LoadPublic(signingKeyPath() + ".pub"); err == nil {
		eo.Pub = pub
	}
	if sg, err := sign.LoadSigner(signingKeyPath()); err == nil {
		eo.Signer = sg
	}
	for _, f := range formats {
		body, _, err := export.Generate(eo, "security-report", f)
		if err != nil {
			reportOK = false
			fmt.Printf("report %s: %v\n", f, err)
			continue
		}
		_ = os.WriteFile(filepath.Join(rd, "report."+f), body, 0o644)
		// the same report goes into the run's reports/ so the dashboard lists, previews and downloads it
		if _, err := api.StoreReport(dyn, filepath.Base(rd), f, "security-report", eo.Title, eo.Classification, body, "cli"); err != nil {
			fmt.Printf("report %s: could not register for the dashboard: %v\n", f, err)
		}
	}
	if reportOK {
		sReport.status = "done"
	} else {
		sReport.status = "failed"
	}
	plan.summary()
	fmt.Printf("\n== result for %s\n", res.Report.Name)
	if rating != "" {
		fmt.Println("   rating:", rating)
	}
	fmt.Printf("   static: %v\n", severityLine(res.Report.Counts()))
	fmt.Printf("   report:       %s\n   evaluation:   %s\n   static audit: %s\n   traces:       %s\n", filepath.Join(rd, "report.html"), filepath.Join(rd, "evaluation.txt"), filepath.Join(rd, "whitebox.json"), filepath.Join(dyn, "traces"))
	fmt.Printf("   dashboard:    this run is listed as %q under Reports (and in the run selector); start it with `avhsol serve` if it is not running\n", filepath.Base(rd))
	return nil
}

func mustAbs(p string) string { a, _ := filepath.Abs(p); return a }

func severityLine(m map[string]int) string {
	var parts []string
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if m[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", m[s], s))
		}
	}
	if len(parts) == 0 {
		return "no findings"
	}
	return strings.Join(parts, ", ")
}

// writeSeeds merges the packaged coding seeds, the no-attack control and any intel-derived seeds into one file in the run directory.
func writeSeeds(rd string) (string, int, error) {
	var all []campaign.Seed
	for _, f := range []string{"seeds/coding-seeds.yaml", "seeds/control-seeds.yaml", "seeds/intel-generated.yaml"} {
		p := home.Resolve(f)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		s, err := campaign.LoadSeeds(p)
		if err != nil {
			return "", 0, err
		}
		all = append(all, s...)
	}
	if len(all) == 0 {
		return "", 0, fmt.Errorf("no attack seeds found (looked for seeds/coding-seeds.yaml under %s)", home.Assets())
	}
	b, err := yaml.Marshal(map[string]any{"seeds": all})
	if err != nil {
		return "", 0, err
	}
	p := filepath.Join(rd, "seeds.yaml")
	return p, len(all), os.WriteFile(p, b, 0o644)
}

// graphReachable reports whether the Neo4j stack answers, without printing anything when it does not.
func graphReachable(ctx context.Context) bool {
	cfg := graph.LoadConfig()
	if cfg.Password == "" {
		return false
	}
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	st, err := graph.Open(c, cfg)
	if err != nil {
		return false
	}
	st.Close(c)
	return true
}
