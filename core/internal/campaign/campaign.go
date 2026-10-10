package campaign

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/41vi4p/agentbreak/core/internal/audit"
	"github.com/41vi4p/agentbreak/core/internal/trace"
)

type TechniqueStat struct {
	Technique string  `json:"technique"`
	Attempts  int     `json:"attempts"`
	Successes int     `json:"successes"`
	ASR       float64 `json:"asr"`
}

// ObjectiveStat is the success rate for one scenario objective over valid runs. Reporting per
// objective keeps a weak objective (secret read) from inflating a strong one (exfiltration).
type ObjectiveStat struct {
	Objective string  `json:"objective"`
	Severity  string  `json:"severity"`
	Successes int     `json:"successes"`
	Valid     int     `json:"valid"`
	Rate      float64 `json:"rate"`
}

type Report struct {
	ScenarioID   string          `json:"scenario_id"`
	Model        string          `json:"model"`
	GuardMode    string          `json:"guard_mode"`
	Offline      bool            `json:"offline_simulated"`
	Attempts     int             `json:"attempts"`
	Errors       int             `json:"errors"` // episodes that failed (e.g. context overflow); excluded from ASR
	Valid        int             `json:"valid_attempts"`
	Successes    int             `json:"successes"`
	ASR          float64         `json:"asr"`
	ByTechnique  []TechniqueStat `json:"by_technique"`
	Static       []trace.Finding `json:"static_audit"`
	ByObjective  []ObjectiveStat `json:"by_objective"`
	TraceIDs     []string        `json:"trace_ids"`
	SuccessTrace []string        `json:"successful_trace_ids"`
}

// Pair is one (seed, surface) attack.
type Pair struct {
	Seed    Seed
	Surface string
}

// AllPairs is the full seed × surface cross product.
func (r *Runner) AllPairs(seeds []Seed) []Pair {
	var ps []Pair
	for _, seed := range seeds {
		for _, sf := range r.Scenario.Surfaces {
			ps = append(ps, Pair{seed, sf.ID})
		}
	}
	return ps
}

// Run executes every seed against every surface `repeats` times (guard mode as configured on the runner).
func (r *Runner) Run(ctx context.Context, seeds []Seed, repeats int, outDir string, log io.Writer) (*Report, []*trace.Trace, error) {
	return r.RunPairs(ctx, r.AllPairs(seeds), repeats, outDir, log)
}

// RunPairs runs a specific list of attacks (used to replay previously successful ones).
func (r *Runner) RunPairs(ctx context.Context, pairs []Pair, repeats int, outDir string, log io.Writer) (*Report, []*trace.Trace, error) {
	if repeats < 1 {
		repeats = 1
	}
	rep := &Report{
		ScenarioID: r.Scenario.ID, Model: r.modelName(), GuardMode: orOff(r.GuardMode), Offline: r.Offline,
		Static: audit.Static(r.Scenario),
	}
	byTech := map[string]*TechniqueStat{}
	objStats := map[string]*ObjectiveStat{}
	var traces []*trace.Trace
	for _, p := range pairs {
		seed, sfID := p.Seed, p.Surface
		for n := 0; n < repeats; n++ {
			tr, err := r.RunAttack(ctx, seed, sfID)
			if err != nil {
				return rep, traces, fmt.Errorf("seed %s: %w", seed.ID, err)
			}
			if outDir != "" {
				if _, err := tr.Save(outDir); err != nil {
					return rep, traces, err
				}
			}
			traces = append(traces, tr)
			st := byTech[seed.Technique]
			if st == nil {
				st = &TechniqueStat{Technique: seed.Technique}
				byTech[seed.Technique] = st
			}
			rep.Attempts++
			if tr.Error != "" && !tr.Success {
				rep.Errors++ // a failed run is not a defended run
				if log != nil {
					fmt.Fprintf(log, "  %-22s %-14s guard=%-7s -> %s\n", seed.ID, sfID, rep.GuardMode, verdictWord(tr))
				}
				continue
			}
			rep.Valid++
			for _, v := range tr.Verdicts {
				o := objStats[v.ObjectiveID]
				if o == nil {
					o = &ObjectiveStat{Objective: v.ObjectiveID, Severity: v.Severity}
					objStats[v.ObjectiveID] = o
				}
				o.Valid++
				if v.Success {
					o.Successes++
				}
			}
			st.Attempts++
			rep.TraceIDs = append(rep.TraceIDs, tr.TraceID)
			if tr.Success {
				st.Successes++
				rep.Successes++
				rep.SuccessTrace = append(rep.SuccessTrace, tr.TraceID)
			}
			if log != nil {
				fmt.Fprintf(log, "  %-22s %-14s guard=%-7s -> %s\n", seed.ID, sfID, rep.GuardMode, verdictWord(tr))
			}
		}
	}
	for _, st := range byTech {
		if st.Attempts > 0 {
			st.ASR = float64(st.Successes) / float64(st.Attempts)
		}
		rep.ByTechnique = append(rep.ByTechnique, *st)
	}
	sort.Slice(rep.ByTechnique, func(i, j int) bool { return rep.ByTechnique[i].Technique < rep.ByTechnique[j].Technique })
	for _, o := range objStats {
		if o.Valid > 0 {
			o.Rate = float64(o.Successes) / float64(o.Valid)
		}
		rep.ByObjective = append(rep.ByObjective, *o)
	}
	sort.Slice(rep.ByObjective, func(i, j int) bool { return rep.ByObjective[i].Objective < rep.ByObjective[j].Objective })
	if rep.Valid > 0 {
		rep.ASR = float64(rep.Successes) / float64(rep.Valid)
	}
	return rep, traces, nil
}

func verdictWord(tr *trace.Trace) string {
	if tr.Success {
		for _, v := range tr.Verdicts {
			if v.Success {
				return "EXPLOITED  (" + v.Evidence + ")"
			}
		}
	}
	if tr.Error != "" {
		return "error: " + tr.Error
	}
	return "resisted"
}

// Regression runs every benign task and returns the utility rate.
type RegressionResult struct {
	Tasks   int      `json:"tasks"`
	Passed  int      `json:"passed"`
	Utility float64  `json:"utility"`
	Failed  []string `json:"failed,omitempty"`
}

func (r *Runner) Regression(ctx context.Context, outDir string, log io.Writer) (*RegressionResult, error) {
	res := &RegressionResult{}
	for _, task := range r.Scenario.BenignTasks {
		tr, ok, checks, err := r.RunBenign(ctx, task)
		if err != nil {
			return nil, fmt.Errorf("benign %s: %w", task.ID, err)
		}
		if outDir != "" {
			if _, err := tr.Save(outDir); err != nil {
				return nil, err
			}
		}
		res.Tasks++
		if ok {
			res.Passed++
		} else {
			res.Failed = append(res.Failed, task.ID)
		}
		if log != nil {
			word := "PASS"
			if !ok {
				word = "FAIL"
				for _, c := range checks {
					if !c.Passed {
						word += fmt.Sprintf(" [%s %s%s%s]", c.Check.Kind, c.Check.Tool, c.Check.Value, c.Check.Domain)
					}
				}
			}
			fmt.Fprintf(log, "  benign %-24s guard=%-7s %s\n", task.ID, orOff(r.GuardMode), word)
		}
	}
	if res.Tasks > 0 {
		res.Utility = float64(res.Passed) / float64(res.Tasks)
	}
	return res, nil
}
