// Package attacker is the autonomous search loop: a UCB1 bandit over
// (technique × surface × mutation-operator) arms, deterministic progress feedback,
// reliability re-runs, and payload minimisation. LLM-written payloads come from a Crafter.
package attacker

import (
	"context"
	"fmt"
	"io"
	"math"
	"math/rand"
	"strings"

	"github.com/41vi4p/agentbreak/core/internal/campaign"
)

type Arm struct {
	Seed     campaign.Seed
	Surface  string
	Operator string
}

func (a Arm) Key() string { return a.Seed.ID + "|" + a.Surface + "|" + a.Operator }

// Attempt is the outcome of one executed payload.
type Attempt struct {
	Payload     string
	Success     bool
	Progress    int
	Note        string
	TraceID     string
	GuardBlocks []string
}

// Executor runs one payload against the target (the campaign Runner in production).
type Executor interface {
	Execute(ctx context.Context, arm Arm, payload string) (Attempt, error)
}

type CraftRequest struct {
	Arm     Arm
	Seed    string // plain rendered seed text
	History []Attempt
}

// Crafter writes LLM-authored payloads (nil => the llm_rewrite operator is not used).
type Crafter interface {
	Craft(ctx context.Context, req CraftRequest) (payload string, err error)
}

type Discovery struct {
	Arm              string  `json:"arm"`
	Technique        string  `json:"technique"`
	Surface          string  `json:"surface"`
	Operator         string  `json:"operator"`
	Payload          string  `json:"payload"`
	MinimizedPayload string  `json:"minimized_payload"`
	Reliability      float64 `json:"reliability"`
	Runs             int     `json:"runs"`
	TraceID          string  `json:"trace_id"`
	Attempt          int     `json:"found_at_attempt"`
}

type ArmStat struct {
	Arm      string  `json:"arm"`
	Pulls    int     `json:"pulls"`
	MeanRwd  float64 `json:"mean_reward"`
	BestProg int     `json:"best_progress"`
}

type Result struct {
	Attempts    int         `json:"attempts"`
	Executions  int         `json:"executions"` // includes reliability + minimisation re-runs
	Discoveries []Discovery `json:"discoveries"`
	Arms        []ArmStat   `json:"arms"`
}

type Config struct {
	Budget      int // bandit pulls
	Reliab      int // total runs used to estimate reliability of a discovery (>=1)
	MinimizeMax int // max extra runs spent shrinking one payload
	StopAfter   int // stop after this many distinct discoveries (0 = use whole budget)
	Seed        int64
	Vars        map[string]string
	Log         io.Writer
}

type armState struct {
	arm   Arm
	pulls int
	sum   float64
	best  int
	found bool
}

func (s *armState) mean() float64 {
	if s.pulls == 0 {
		return 0
	}
	return s.sum / float64(s.pulls)
}

// BuildArms enumerates seed × surface × operator.
func BuildArms(seeds []campaign.Seed, surfaces []string, ops []string) []Arm {
	var arms []Arm
	for _, s := range seeds {
		for _, sf := range surfaces {
			for _, op := range ops {
				arms = append(arms, Arm{Seed: s, Surface: sf, Operator: op})
			}
		}
	}
	return arms
}

func selectArm(states []*armState, total int, rng *rand.Rand) *armState {
	// Explore: pull every arm once, in random order, before using confidence bounds.
	var fresh []*armState
	for _, st := range states {
		if st.pulls == 0 {
			fresh = append(fresh, st)
		}
	}
	if len(fresh) > 0 {
		return fresh[rng.Intn(len(fresh))]
	}
	best, bestScore := states[0], math.Inf(-1)
	for _, st := range states {
		if st.found {
			continue // already broken: spend budget on other arms
		}
		score := st.mean() + math.Sqrt(2*math.Log(float64(total))/float64(st.pulls))
		if score > bestScore {
			best, bestScore = st, score
		}
	}
	return best
}

// Hunt runs the adaptive search.
func Hunt(ctx context.Context, ex Executor, cr Crafter, arms []Arm, cfg Config) (*Result, error) {
	if len(arms) == 0 {
		return nil, fmt.Errorf("no arms")
	}
	if cr == nil {
		for _, a := range arms {
			if a.Operator == OpLLMRewrite {
				return nil, fmt.Errorf("arm %s needs a Crafter (llm_rewrite) but none was provided", a.Key())
			}
		}
	}
	if cfg.Reliab < 1 {
		cfg.Reliab = 1
	}
	rng := rand.New(rand.NewSource(cfg.Seed))
	states := make([]*armState, len(arms))
	for i, a := range arms {
		states[i] = &armState{arm: a}
	}
	res := &Result{}
	var history []Attempt
	logf := func(f string, a ...any) {
		if cfg.Log != nil {
			fmt.Fprintf(cfg.Log, f, a...)
		}
	}

	for res.Attempts < cfg.Budget {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		st := selectArm(states, res.Attempts+1, rng)
		arm := st.arm
		plain := arm.Seed.RenderPlain(cfg.Vars)
		var payload string
		if arm.Operator == OpLLMRewrite {
			p, err := cr.Craft(ctx, CraftRequest{Arm: arm, Seed: plain, History: history})
			if err != nil || strings.TrimSpace(p) == "" {
				logf("  [craft failed: %v]\n", err)
				st.pulls++
				res.Attempts++
				continue
			}
			payload = p
		} else {
			payload = Apply(arm.Operator, plain)
		}

		at, err := ex.Execute(ctx, arm, payload)
		if err != nil {
			return res, fmt.Errorf("arm %s: %w", arm.Key(), err)
		}
		res.Attempts++
		res.Executions++
		st.pulls++
		rwd := float64(at.Progress) / 5.0
		if at.Success {
			rwd = 1
		}
		st.sum += rwd
		if at.Progress > st.best {
			st.best = at.Progress
		}
		history = append(history, Attempt{Payload: payload, Success: at.Success, Progress: at.Progress, Note: at.Note, TraceID: at.TraceID, GuardBlocks: at.GuardBlocks})
		if len(history) > 12 {
			history = history[len(history)-12:]
		}
		logf("  #%-3d %-44s progress=%d %s\n", res.Attempts, arm.Key(), at.Progress, at.Note)

		if at.Success {
			st.found = true
			d, extra, err := confirm(ctx, ex, arm, payload, at, cfg, res.Attempts)
			res.Executions += extra
			if err != nil {
				return res, err
			}
			res.Discoveries = append(res.Discoveries, d)
			logf("  >>> DISCOVERY %s reliability=%.0f%% (%d runs); minimized %d -> %d bytes\n", arm.Key(), d.Reliability*100, d.Runs, len(d.Payload), len(d.MinimizedPayload))
			if cfg.StopAfter > 0 && len(res.Discoveries) >= cfg.StopAfter {
				break
			}
		}
	}
	for _, st := range states {
		if st.pulls > 0 {
			res.Arms = append(res.Arms, ArmStat{Arm: st.arm.Key(), Pulls: st.pulls, MeanRwd: st.mean(), BestProg: st.best})
		}
	}
	return res, nil
}

// confirm re-runs a winning payload for a reliability estimate, then shrinks it.
func confirm(ctx context.Context, ex Executor, arm Arm, payload string, first Attempt, cfg Config, found int) (Discovery, int, error) {
	extra, wins, runs := 0, 1, 1
	for i := 1; i < cfg.Reliab; i++ {
		at, err := ex.Execute(ctx, arm, payload)
		if err != nil {
			return Discovery{}, extra, err
		}
		extra++
		runs++
		if at.Success {
			wins++
		}
	}
	min, n, err := Minimize(ctx, ex, arm, payload, cfg.MinimizeMax)
	extra += n
	if err != nil {
		return Discovery{}, extra, err
	}
	return Discovery{
		Arm: arm.Key(), Technique: arm.Seed.Technique, Surface: arm.Surface, Operator: arm.Operator,
		Payload: payload, MinimizedPayload: min, Reliability: float64(wins) / float64(runs), Runs: runs,
		TraceID: first.TraceID, Attempt: found,
	}, extra, nil
}

func units(payload string) []string {
	lines := strings.Split(payload, "\n")
	if len(lines) > 1 {
		return lines
	}
	// single line: split on sentence boundaries
	parts := strings.SplitAfter(payload, ". ")
	return parts
}

// Minimize greedily drops lines/sentences while the payload still succeeds.
// maxRuns bounds the extra executions; returns the smallest succeeding payload found.
func Minimize(ctx context.Context, ex Executor, arm Arm, payload string, maxRuns int) (string, int, error) {
	us := units(payload)
	runs := 0
	for i := 0; i < len(us) && runs < maxRuns && len(us) > 1; {
		cand := append(append([]string{}, us[:i]...), us[i+1:]...)
		text := strings.Join(cand, joiner(payload))
		if strings.TrimSpace(text) == "" {
			i++
			continue
		}
		at, err := ex.Execute(ctx, arm, text)
		if err != nil {
			return payload, runs, err
		}
		runs++
		if at.Success {
			us = cand // keep removal; same index now points to next unit
		} else {
			i++
		}
	}
	return strings.Join(us, joiner(payload)), runs, nil
}

func joiner(payload string) string {
	if strings.Contains(payload, "\n") {
		return "\n"
	}
	return ""
}
