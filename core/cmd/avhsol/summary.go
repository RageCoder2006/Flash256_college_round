package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/41vi4p/avhsol/core/internal/home"
	"os"
	"path/filepath"

	"github.com/41vi4p/avhsol/core/internal/eval"
	"github.com/41vi4p/avhsol/core/internal/export"
	"github.com/41vi4p/avhsol/core/internal/sign"
)

// buildEvaluation reads a run directory exactly as `avhsol export` does and summarises it.
func buildEvaluation(dir, scenarioDir, scenarioID string) (eval.Evaluation, error) {
	o := export.Options{Dir: dir, ScenarioDir: scenarioDir, Scenario: scenarioID, NoIntel: true}
	if pub, err := sign.LoadPublic(signingKeyPath() + ".pub"); err == nil {
		o.Pub = pub
	}
	r, err := export.Build(o)
	if err != nil {
		return eval.Evaluation{}, err
	}
	return eval.Summarize(r), nil
}

// evalScenarioDir is where the evaluation looks up scenarios by id; a whitebox run points it at its generated scenario.
var evalScenarioOverride string

func evalScenarioDir() string {
	if evalScenarioOverride != "" {
		return evalScenarioOverride
	}
	return home.Resolve("scenarios")
}

// printEvaluation shows the evaluation at the end of a run. A directory with no traces simply prints nothing.
func printEvaluation(dir string) {
	if m, _ := filepath.Glob(filepath.Join(dir, "traces", "*.json")); len(m) == 0 {
		return
	}
	e, err := buildEvaluation(dir, evalScenarioDir(), "")
	if err != nil {
		return
	}
	fmt.Println()
	fmt.Print(eval.Text(e))
}

func cmdSummary(args []string) error {
	fs := flag.NewFlagSet("summary", flag.ExitOnError)
	in := fs.String("in", "out", "run directory (traces/)")
	scenarios := fs.String("scenarios", "scenarios", "directory with the scenario files")
	sc := fs.String("scenario", "", "scenario id (default: the one with the most attack runs)")
	asJSON := fs.Bool("json", false, "print the evaluation as JSON")
	_ = fs.Parse(args)
	e, err := buildEvaluation(*in, home.Resolve(*scenarios), *sc)
	if err != nil {
		return err
	}
	if *asJSON {
		b, _ := json.MarshalIndent(e, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Print(eval.Text(e))
	return nil
}

var _ = os.Stdout
