// Package tools is the one list of what AVHSOL can do on request: the Settings page shows it, and the MCP server
// (internal/mcpserver) exposes it to Claude Code or any other MCP client. Each tool has a minimum role (the same ladder
// as the dashboard API) and an effect, so what a client may call is decided in one place.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

// Roles mirror api.Role so a caller's role compares directly.
const (
	Viewer   = 1
	Analyst  = 2
	Operator = 3
	Admin    = 4
)

// Effects: what calling the tool can change.
const (
	EffectRead     = "read"     // reads files and returns text; changes nothing
	EffectWrites   = "writes"   // writes a report or file inside AVHSOL's own directories
	EffectLaunches = "launches" // starts agents or attacks (runs the audited agent's code in a sandbox)
)

// Env is what handlers may touch.
type Env struct {
	OutDirs []string // run directories to list besides the state directory's runs/
	Exe     string   // this binary, used by tools that start a run
}

// Result is what a handler returns. Data is attacker-influenceable whenever Untrusted is set (trace payloads, scanned
// source, fetched advisory text), and the MCP layer labels it as data for the calling model.
type Result struct {
	Summary   string `json:"summary"`
	Data      any    `json:"data,omitempty"`
	Untrusted bool   `json:"untrusted"`
}

// Tool is one callable capability.
type Tool struct {
	Name        string                                                                   `json:"name"`
	Title       string                                                                   `json:"title"`
	Description string                                                                   `json:"description"`
	Schema      map[string]any                                                           `json:"input_schema"`
	MinRole     int                                                                      `json:"min_role"`
	Effect      string                                                                   `json:"effect"`
	Handler     func(ctx context.Context, env Env, args json.RawMessage) (Result, error) `json:"-"`
}

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func boolean(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}
func integer(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

// All returns every registered tool, ordered by effect then name.
func All() []Tool {
	ts := []Tool{
		scanCodebase, auditScenario, listCatalog, listRuns, listTraces, getTrace, verifyTrace, summary, intelSearch, status,
		exportReport, auditCodebase,
	}
	order := map[string]int{EffectRead: 0, EffectWrites: 1, EffectLaunches: 2}
	sort.SliceStable(ts, func(i, j int) bool {
		if order[ts[i].Effect] != order[ts[j].Effect] {
			return order[ts[i].Effect] < order[ts[j].Effect]
		}
		return ts[i].Name < ts[j].Name
	})
	return ts
}

// Find returns the named tool.
func Find(name string) (Tool, bool) {
	for _, t := range All() {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

// Call runs a tool after checking arguments are a JSON object.
func Call(ctx context.Context, env Env, t Tool, args json.RawMessage) (Result, error) {
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	var probe map[string]any
	if err := json.Unmarshal(args, &probe); err != nil {
		return Result{}, fmt.Errorf("arguments must be a JSON object: %w", err)
	}
	return t.Handler(ctx, env, args)
}

// Default exposure over MCP when a deployment has not chosen: everything that only reads, plus report export.
// Tools that launch agents are off until an administrator turns them on.
func DefaultExposed(t Tool) bool { return t.Effect != EffectLaunches }
