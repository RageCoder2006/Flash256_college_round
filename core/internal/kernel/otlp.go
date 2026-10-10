// Package kernel is the bridge to TRIVEKTRA's eBPF agent. AgentBreak emits one OTLP/HTTP JSON
// "execute_tool" span per sandboxed tool call, tagged with the sandbox's real PID. TRIVEKTRA's
// loopback receiver (POST /v1/traces) ledgers it and can correlate it with the kernel process
// tree, so a guard verdict can be compared with what the kernel actually saw.
package kernel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

type Emitter struct {
	URL   string // e.g. http://127.0.0.1:4318
	Agent string
	HTTP  *http.Client
}

func New(url string) *Emitter {
	return &Emitter{URL: url, Agent: "agentbreak-target", HTTP: &http.Client{Timeout: 3 * time.Second}}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func strAttr(k, v string) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"stringValue": v}}
}

// Body builds the OTLP JSON payload for one tool execution.
func (e *Emitter) Body(traceID, tool string, pid int, start, end time.Time) ([]byte, error) {
	if len(traceID) != 32 {
		traceID = randHex(16)
	}
	span := map[string]any{
		"traceId": traceID, "spanId": randHex(8), "name": "execute_tool",
		"startTimeUnixNano": strconv.FormatInt(start.UnixNano(), 10),
		"endTimeUnixNano":   strconv.FormatInt(end.UnixNano(), 10),
		"attributes": []any{
			strAttr("gen_ai.operation.name", "execute_tool"),
			strAttr("gen_ai.tool.name", tool),
			strAttr("gen_ai.agent.name", e.Agent),
		},
	}
	return json.Marshal(map[string]any{"resourceSpans": []any{map[string]any{
		"resource":   map[string]any{"attributes": []any{strAttr("process.pid", strconv.Itoa(pid))}},
		"scopeSpans": []any{map[string]any{"spans": []any{span}}},
	}}})
}

// EmitTool sends the span. Best effort: TRIVEKTRA is optional, never a dependency of a run.
func (e *Emitter) EmitTool(ctx context.Context, traceID, tool string, pid int, start, end time.Time) error {
	b, err := e.Body(traceID, tool, pid, start, end)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", e.URL+"/v1/traces", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	res, err := e.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("otlp receiver: HTTP %d", res.StatusCode)
	}
	return nil
}
