package campaign

import (
	"context"
	"fmt"
	"strings"

	"github.com/41vi4p/avhsol/core/internal/httpagent"
	"github.com/41vi4p/avhsol/core/internal/scenario"
	"github.com/41vi4p/avhsol/core/internal/trace"
	"github.com/41vi4p/avhsol/core/internal/world"
)

// runHTTPEpisode drives an agent that is only reachable over HTTP. It cannot see inside the agent: the trace holds
// the message sent, the moment the agent fetched the poisoned document, and its reply. The oracles still decide
// success from what reached the canary sink, so a breach is real even though the path to it is not visible.
func (r *Runner) runHTTPEpisode(ctx context.Context, tr *trace.Trace, w *world.World, sf *scenario.Surface, payload string, turns []string) error {
	spec := r.CLI.HTTP
	tr.Observability = "blackbox"
	task := strings.Join(turns, " ")
	var surfaceURL string
	placement := spec.Placement
	var cs *httpagent.ContentServer
	if placement == "url" && sf != nil && sf.Kind == "document" {
		if d, ok := w.Documents[sf.Target]; ok {
			var err error
			if cs, err = httpagent.StartContentServer(map[string]string{sf.Target: d.Text}, spec.PublicHost); err != nil {
				return err
			}
			defer cs.Close()
			surfaceURL = cs.URL(sf.Target)
		}
	}
	if cs == nil {
		placement = "inline" // no document to serve for this surface: fall back to direct injection
	}
	msgSpec := *spec
	if placement == "inline" {
		msgSpec.Placement, msgSpec.TaskTemplate = "inline", ""
		msgSpec.Defaults()
	}
	message := msgSpec.Message(task, surfaceURL, payload)
	_, _ = tr.Append(trace.StepUserTurn, nowMs(), map[string]any{"text": message})
	res := spec.Drive(ctx, message)
	if cs != nil {
		for _, f := range cs.Fetches() {
			src := "retrieved:" + sf.ID
			w.MarkUntrusted(src)
			_, _ = tr.Append(trace.StepToolResult, nowMs(), map[string]any{"id": "fetch", "content": f.Content, "is_error": false, "source": src})
		}
	}
	_, _ = tr.Append(trace.StepLLMResponse, nowMs(), map[string]any{"text": res.Reply, "tool_calls": []map[string]any{}, "stop_reason": "stop"})
	i := w.ExternalCall("cli_output", map[string]any{})
	w.ExternalResult(i, res.Reply)
	tr.FinalText = res.Reply
	if res.Err != "" {
		tr.Error = fmt.Sprintf("agent endpoint: %s", res.Err)
	}
	return nil
}
