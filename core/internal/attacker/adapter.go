package attacker

import (
	"context"
	"strings"

	"github.com/41vi4p/agentbreak/core/internal/campaign"
	"github.com/41vi4p/agentbreak/core/internal/harness"
	"github.com/41vi4p/agentbreak/core/internal/trace"
)

// RunnerExecutor executes payloads through the campaign Runner and saves traces.
type RunnerExecutor struct {
	R      *campaign.Runner
	OutDir string
}

func (e *RunnerExecutor) Execute(ctx context.Context, arm Arm, payload string) (Attempt, error) {
	tr, err := e.R.RunPayload(ctx, trace.Attack{
		SeedID: arm.Seed.ID, Technique: arm.Seed.Technique, Surface: arm.Surface, Encoding: arm.Operator, Payload: payload,
	})
	if err != nil {
		return Attempt{}, err
	}
	if e.OutDir != "" {
		if _, err := tr.Save(e.OutDir); err != nil {
			return Attempt{}, err
		}
	}
	var blocks []string
	for _, s := range tr.Steps {
		if s.Type == trace.StepGuard {
			if d, _ := s.Data["decision"].(string); d == "deny" || d == "approve" {
				if why, _ := s.Data["reason"].(string); why != "" {
					blocks = append(blocks, why)
				}
			}
		}
	}
	return Attempt{Payload: payload, Success: tr.Success, Progress: tr.Progress, Note: tr.ProgressNote, TraceID: tr.TraceID, GuardBlocks: blocks}, nil
}

// HarnessCrafter asks the TS AttackerAgent (pi) for LLM-written payloads.
type HarnessCrafter struct {
	R           *campaign.Runner
	Objective   string
	SurfaceKind func(surfaceID string) string
}

func (c *HarnessCrafter) Craft(ctx context.Context, req CraftRequest) (string, error) {
	hist := make([]harness.CraftHistory, 0, len(req.History))
	for _, h := range req.History {
		hist = append(hist, harness.CraftHistory{Payload: h.Payload, Progress: h.Progress, Note: h.Note, GuardBlocks: orEmpty(h.GuardBlocks)})
	}
	llm := c.R.LLM
	llm.Kind = "openai"
	res, err := c.R.Harness.CraftPayload(ctx, harness.CraftRequest{
		LLM: llm, Objective: c.Objective, SurfaceKind: c.SurfaceKind(req.Arm.Surface), TargetTools: c.R.Scenario.Tools,
		Technique: req.Arm.Seed.Technique, Operator: req.Arm.Operator, SeedText: req.Seed,
		AttackerEmail: campaign.AttackerEmail, History: hist,
	})
	if err != nil {
		return "", err
	}
	if res.Error != "" {
		return "", &craftErr{res.Error}
	}
	return strings.TrimSpace(res.Payload), nil
}

type craftErr struct{ s string }

func (e *craftErr) Error() string { return e.s }

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
