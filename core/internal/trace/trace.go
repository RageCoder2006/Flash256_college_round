// Package trace defines the reproducible attack-trace format: a hash-chained,
// append-only list of steps plus the metadata needed to re-run the episode.
package trace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Step types recorded in a trace.
const (
	StepUserTurn    = "user_turn"
	StepLLMResponse = "llm_response"
	StepToolCall    = "tool_call"
	StepToolResult  = "tool_result"
	StepGuard       = "guard"
	StepSandbox     = "sandbox_event"
	StepKernel      = "kernel_event"
)

type Step struct {
	Seq      int            `json:"seq"`
	Type     string         `json:"type"`
	TS       int64          `json:"ts"`
	Data     map[string]any `json:"data"`
	PrevHash string         `json:"prev_hash"`
	Hash     string         `json:"hash"`
}

// Verdict is one deterministic oracle result for a scenario objective.
type Verdict struct {
	ObjectiveID string   `json:"objective_id"`
	Success     bool     `json:"success"`
	Severity    string   `json:"severity"`
	ASI         []string `json:"asi,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
}

// Finding is an auditor result (permission audit / confused deputy / capability violation).
type Finding struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Tool     string `json:"tool,omitempty"`
	Detail   string `json:"detail"`
	StepSeq  int    `json:"step_seq,omitempty"`
}

// Attack records how the episode's payload was produced (lineage for reproduction).
type Attack struct {
	SeedID    string `json:"seed_id"`
	Technique string `json:"technique"`
	Surface   string `json:"surface"`
	Encoding  string `json:"encoding,omitempty"`
	Payload   string `json:"payload"`
	ParentID  string `json:"parent_id,omitempty"`
}

type Trace struct {
	TraceID        string    `json:"trace_id"`
	ScenarioID     string    `json:"scenario_id"`
	ScenarioSHA256 string    `json:"scenario_sha256"`
	Model          string    `json:"model"`
	GuardMode      string    `json:"guard_mode"`
	PolicyHash     string    `json:"policy_hash,omitempty"`
	Kind           string    `json:"kind"` // attack | benign
	Attack         *Attack   `json:"attack,omitempty"`
	SystemPrompt   string    `json:"system_prompt"`
	UserTurns      []string  `json:"user_turns"`
	Steps          []Step    `json:"steps"`
	Verdicts       []Verdict `json:"verdicts"`
	Findings       []Finding `json:"findings"`
	Success        bool      `json:"success"`  // any attack objective achieved
	Progress       int       `json:"progress"` // 0..5 deterministic attack progress
	ProgressNote   string    `json:"progress_note,omitempty"`
	FinalText      string    `json:"final_text"`
	Error          string    `json:"error,omitempty"`
	StartedAt      time.Time `json:"started_at"`
	DurationMs     int64     `json:"duration_ms"`
}

func stepHash(prev string, typ string, ts int64, data map[string]any) (string, error) {
	// encoding/json sorts map keys, so this is canonical for a given content.
	b, err := json.Marshal(struct {
		Prev string         `json:"prev"`
		Type string         `json:"type"`
		TS   int64          `json:"ts"`
		Data map[string]any `json:"data"`
	}{prev, typ, ts, data})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Append adds a step and extends the hash chain.
func (t *Trace) Append(typ string, ts int64, data map[string]any) (int, error) {
	prev := ""
	if n := len(t.Steps); n > 0 {
		prev = t.Steps[n-1].Hash
	}
	if data == nil {
		data = map[string]any{}
	}
	h, err := stepHash(prev, typ, ts, data)
	if err != nil {
		return 0, err
	}
	seq := len(t.Steps)
	t.Steps = append(t.Steps, Step{Seq: seq, Type: typ, TS: ts, Data: data, PrevHash: prev, Hash: h})
	return seq, nil
}

// Verify recomputes the chain and reports the first tampered step.
func (t *Trace) Verify() error {
	prev := ""
	for i, s := range t.Steps {
		// A trace round-tripped through JSON may carry float64 numbers etc.; hashes are
		// computed over the JSON encoding, which is stable across that round trip.
		h, err := stepHash(prev, s.Type, s.TS, s.Data)
		if err != nil {
			return err
		}
		if s.PrevHash != prev || s.Hash != h || s.Seq != i {
			return fmt.Errorf("trace %s: chain broken at step %d", t.TraceID, i)
		}
		prev = s.Hash
	}
	return nil
}

// HeadHash is the hash of the last step; identical replays yield identical heads.
func (t *Trace) HeadHash() string {
	if len(t.Steps) == 0 {
		return ""
	}
	return t.Steps[len(t.Steps)-1].Hash
}

func (t *Trace) Save(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, t.TraceID+".json")
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return "", err
	}
	return p, os.WriteFile(p, b, 0o644)
}

func Load(path string) (*Trace, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Trace
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, err
	}
	return &t, nil
}
