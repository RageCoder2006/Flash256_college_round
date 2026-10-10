package campaign

import (
	"context"
	"fmt"
	"io"

	"github.com/41vi4p/agentbreak/core/internal/guard"
	"github.com/41vi4p/agentbreak/core/internal/trace"
)

type AblationRow struct {
	Variant   string  `json:"variant"` // without | only
	Defense   string  `json:"defense"`
	Successes int     `json:"successes"`
	Attempts  int     `json:"attempts"`
	ASR       float64 `json:"asr"`
}

type Validation struct {
	Baseline      *Report           `json:"baseline"`
	Defended      *Report           `json:"defended"`
	Replayed      int               `json:"replayed_exploits"`
	Blocked       int               `json:"blocked"`
	BlockedPct    float64           `json:"blocked_pct"`
	RegressionOff *RegressionResult `json:"regression_guard_off"`
	RegressionOn  *RegressionResult `json:"regression_guard_on"`
	UtilityDelta  float64           `json:"utility_delta"`
	Ablation      []AblationRow     `json:"ablation,omitempty"`
	Guard         *guard.Metrics    `json:"guard_metrics,omitempty"`
}

func without(all []string, drop string) []string {
	var out []string
	for _, d := range all {
		if d != drop {
			out = append(out, d)
		}
	}
	return out
}

func (r *Runner) setGuard(ctx context.Context, g *guard.Client, mode string, defenses []string) error {
	r.GuardMode = mode
	if err := g.PushPolicy(ctx, guard.PolicyFromScenario(r.Scenario, defenses)); err != nil {
		return err
	}
	return g.SetMode(ctx, mode)
}

// Validate is the defense-validation + regression pipeline:
//  1. attack with the guard off (baseline)
//  2. replay every successful attack with the guard enforcing
//  3. run the benign task suite with the guard off and on
//  4. (optional) knock out one defense at a time to see which ones are load-bearing
//
// SeverityWinner reports whether a trace achieved a critical objective. Replays use this so a weak
// objective (secret read) never counts as an exploit worth replaying.
func SeverityWinner(tr *trace.Trace) bool {
	for _, v := range tr.Verdicts {
		if v.Success && v.Severity == "critical" {
			return true
		}
	}
	return false
}

// Validate is the defense-validation + regression pipeline. If prior is non-nil it supplies the
// baseline attack traces (guard-off) instead of re-running the attack phase.
func (r *Runner) Validate(ctx context.Context, g *guard.Client, seeds []Seed, repeats int, ablate bool, outDir string, log io.Writer, prior []*trace.Trace) (*Validation, error) {
	say := func(f string, a ...any) {
		if log != nil {
			fmt.Fprintf(log, f, a...)
		}
	}
	v := &Validation{}
	all := guard.AllDefenses

	var baseTraces []*trace.Trace
	if prior != nil {
		say("== 1/4 baseline: reusing %d saved guard-off attack traces\n", len(prior))
		baseTraces = prior
		v.Baseline = &Report{ScenarioID: r.Scenario.ID, Model: r.modelName(), GuardMode: "off", Offline: r.Offline}
		for _, tr := range prior {
			v.Baseline.Attempts++
			if tr.Error != "" && !tr.Success {
				v.Baseline.Errors++
				continue
			}
			v.Baseline.Valid++
			if SeverityWinner(tr) {
				v.Baseline.Successes++
			}
		}
		if v.Baseline.Valid > 0 {
			v.Baseline.ASR = float64(v.Baseline.Successes) / float64(v.Baseline.Valid)
		}
	} else {
		say("== 1/4 baseline attack campaign, guard=off\n")
		if err := r.setGuard(ctx, g, "off", all); err != nil {
			return nil, err
		}
		base, bt, err := r.Run(ctx, seeds, repeats, outDir, log)
		if err != nil {
			return nil, err
		}
		v.Baseline, baseTraces = base, bt
	}

	byID := map[string]Seed{}
	for _, s := range seeds {
		byID[s.ID] = s
	}
	var winners []Pair
	for _, tr := range baseTraces {
		if SeverityWinner(tr) && tr.Attack != nil {
			winners = append(winners, Pair{Seed: byID[tr.Attack.SeedID], Surface: tr.Attack.Surface})
		}
	}
	v.Replayed = len(winners)

	say("\n== 2/4 replay %d successful exploits, guard=enforce\n", len(winners))
	if err := g.Reset(ctx); err != nil {
		return nil, err
	}
	if err := r.setGuard(ctx, g, "enforce", all); err != nil {
		return nil, err
	}
	def, _, err := r.RunPairs(ctx, winners, 1, outDir, log)
	if err != nil {
		return nil, err
	}
	v.Defended = def
	v.Blocked = def.Attempts - def.Successes
	if def.Attempts > 0 {
		v.BlockedPct = float64(v.Blocked) / float64(def.Attempts)
	}
	if m, err := g.Metrics(ctx); err == nil {
		v.Guard = m
	}

	say("\n== 3/4 regression: benign tasks\n")
	if err := r.setGuard(ctx, g, "off", all); err != nil {
		return nil, err
	}
	if v.RegressionOff, err = r.Regression(ctx, outDir, log); err != nil {
		return nil, err
	}
	if err := r.setGuard(ctx, g, "enforce", all); err != nil {
		return nil, err
	}
	if v.RegressionOn, err = r.Regression(ctx, outDir, log); err != nil {
		return nil, err
	}
	v.UtilityDelta = v.RegressionOn.Utility - v.RegressionOff.Utility

	if ablate && len(winners) > 0 {
		say("\n== 4/4 ablation: each defense removed, then each defense alone (guard=enforce)\n")
		for _, d := range all {
			if err := r.setGuard(ctx, g, "enforce", without(all, d)); err != nil {
				return nil, err
			}
			rep, _, err := r.RunPairs(ctx, winners, 1, "", nil)
			if err != nil {
				return nil, err
			}
			row := AblationRow{Variant: "without", Defense: d, Successes: rep.Successes, Attempts: rep.Attempts, ASR: rep.ASR}
			v.Ablation = append(v.Ablation, row)
			say("  without %-3s -> %d/%d exploits succeed\n", d, row.Successes, row.Attempts)
		}
		for _, d := range all {
			if err := r.setGuard(ctx, g, "enforce", []string{d}); err != nil {
				return nil, err
			}
			rep, _, err := r.RunPairs(ctx, winners, 1, "", nil)
			if err != nil {
				return nil, err
			}
			row := AblationRow{Variant: "only", Defense: d, Successes: rep.Successes, Attempts: rep.Attempts, ASR: rep.ASR}
			v.Ablation = append(v.Ablation, row)
			say("  only    %-3s -> %d/%d exploits succeed\n", d, row.Successes, row.Attempts)
		}
	}
	// leave the guard in a known state
	_ = r.setGuard(ctx, g, "enforce", all)
	return v, nil
}
