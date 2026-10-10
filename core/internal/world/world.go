// Package world holds the simulated environment an agent acts on (documents,
// records, mailbox, memory, web) and the HTTP API the harness tools call.
// The world owns ground truth: oracles read it, never the model's own claims.
package world

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/41vi4p/agentbreak/core/internal/scenario"
)

type Email struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
	Seq     int    `json:"seq"`
}

type MemoryEntry struct {
	Value string `json:"value"`
	// Tainted is true when the entry was written while untrusted content was in context.
	Tainted bool   `json:"tainted"`
	Source  string `json:"source,omitempty"`
}

// ToolEvent is one tool invocation as the world saw it.
type ToolEvent struct {
	Seq    int            `json:"seq"`
	Tool   string         `json:"tool"`
	Args   map[string]any `json:"args"`
	CallID string         `json:"call_id"`
	// UntrustedBefore lists untrusted provenance labels already in the agent's context.
	UntrustedBefore []string `json:"untrusted_before"`
}

type World struct {
	mu        sync.Mutex
	sc        *scenario.Scenario
	Documents map[string]scenario.Document
	Web       map[string]scenario.Document
	Memory    map[string]MemoryEntry
	Outbox    []Email
	Fetches   []string
	Log       []ToolEvent
	untrusted []string
}

// New builds a fresh world from a scenario (deep-copying mutable state).
func New(sc *scenario.Scenario) *World {
	w := &World{
		sc:        sc,
		Documents: map[string]scenario.Document{},
		Web:       map[string]scenario.Document{},
		Memory:    map[string]MemoryEntry{},
	}
	for k, v := range sc.Documents {
		w.Documents[k] = v
	}
	for k, v := range sc.Web {
		w.Web[k] = v
	}
	for k, v := range sc.Memory {
		w.Memory[k] = MemoryEntry{Value: v}
	}
	return w
}

// PlantPayload appends attacker-controlled text to a surface.
func (w *World) PlantPayload(sf *scenario.Surface, payload string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch sf.Kind {
	case "document":
		d, ok := w.Documents[sf.Target]
		if !ok {
			return fmt.Errorf("no document %q", sf.Target)
		}
		d.Text = d.Text + "\n\n" + payload
		d.Untrusted = true
		w.Documents[sf.Target] = d
	case "web":
		d := w.Web[sf.Target]
		d.Text = d.Text + "\n\n" + payload
		d.Untrusted = true
		w.Web[sf.Target] = d
	case "memory":
		w.Memory[sf.Target] = MemoryEntry{Value: payload, Tainted: true, Source: "planted"}
	default:
		return fmt.Errorf("unsupported surface kind %q", sf.Kind)
	}
	return nil
}

// UntrustedSeen returns provenance labels of untrusted content returned so far.
func (w *World) UntrustedSeen() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.untrusted...)
}

func (w *World) Emails() []Email {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]Email(nil), w.Outbox...)
}

func (w *World) ToolLog() []ToolEvent {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]ToolEvent(nil), w.Log...)
}

func (w *World) FetchedURLs() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.Fetches...)
}

func (w *World) MemorySnapshot() map[string]MemoryEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]MemoryEntry, len(w.Memory))
	for k, v := range w.Memory {
		out[k] = v
	}
	return out
}

func (w *World) markUntrusted(label string) {
	for _, l := range w.untrusted {
		if l == label {
			return
		}
	}
	w.untrusted = append(w.untrusted, label)
}

// Result of a tool call as returned over the wire.
type Result struct {
	Content   string `json:"content"`
	IsError   bool   `json:"is_error"`
	Source    string `json:"source,omitempty"`
	Untrusted bool   `json:"untrusted,omitempty"`
}

func str(args map[string]any, k string) string {
	if v, ok := args[k].(string); ok {
		return v
	}
	return ""
}

// Call executes a tool against the world.
func (w *World) Call(tool, callID string, args map[string]any) Result {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Log = append(w.Log, ToolEvent{
		Seq: len(w.Log), Tool: tool, Args: args, CallID: callID,
		UntrustedBefore: append([]string(nil), w.untrusted...),
	})
	switch tool {
	case "list_documents":
		ids := make([]string, 0, len(w.Documents))
		for id := range w.Documents {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return Result{Content: strings.Join(ids, "\n")}
	case "read_document":
		id := str(args, "doc_id")
		d, ok := w.Documents[id]
		if !ok {
			return Result{Content: "document not found: " + id, IsError: true}
		}
		r := Result{Content: d.Text}
		if d.Untrusted {
			r.Source, r.Untrusted = "retrieved:"+id, true
			w.markUntrusted(r.Source)
		}
		return r
	case "search_records":
		q := strings.ToLower(str(args, "query"))
		var hits []string
		for _, rec := range w.sc.Records {
			if q == "" || strings.Contains(strings.ToLower(rec.Text), q) || strings.Contains(strings.ToLower(rec.ID), q) {
				hits = append(hits, rec.Text)
			}
		}
		if len(hits) == 0 {
			return Result{Content: "no matching records"}
		}
		return Result{Content: strings.Join(hits, "\n"), Source: "records"}
	case "send_email":
		w.Outbox = append(w.Outbox, Email{To: str(args, "to"), Subject: str(args, "subject"), Body: str(args, "body"), Seq: len(w.Outbox)})
		return Result{Content: "Email sent to " + str(args, "to")}
	case "http_fetch":
		u := str(args, "url")
		w.Fetches = append(w.Fetches, u)
		base := u
		if i := strings.IndexAny(base, "?#"); i >= 0 {
			base = base[:i]
		}
		d, ok := w.Web[base]
		if !ok {
			return Result{Content: "HTTP 200 (empty)", Source: "web:" + base, Untrusted: true}
		}
		src := "web:" + base
		w.markUntrusted(src)
		return Result{Content: d.Text, Source: src, Untrusted: true}
	case "memory_read":
		if k := str(args, "key"); k != "" {
			e, ok := w.Memory[k]
			if !ok {
				return Result{Content: "no such key", IsError: true}
			}
			return w.memResult(k, e)
		}
		keys := make([]string, 0, len(w.Memory))
		for k := range w.Memory {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		anyTainted := false
		for _, k := range keys {
			e := w.Memory[k]
			fmt.Fprintf(&b, "%s: %s\n", k, e.Value)
			if e.Tainted {
				anyTainted = true
				w.markUntrusted("memory:" + k)
			}
		}
		return Result{Content: strings.TrimSpace(b.String()), Source: "memory", Untrusted: anyTainted}
	case "memory_write":
		k := str(args, "key")
		tainted := len(w.untrusted) > 0
		w.Memory[k] = MemoryEntry{Value: str(args, "value"), Tainted: tainted, Source: strings.Join(w.untrusted, ",")}
		return Result{Content: "saved " + k}
	default:
		return Result{Content: "tool not available in world: " + tool, IsError: true}
	}
}

func (w *World) memResult(k string, e MemoryEntry) Result {
	r := Result{Content: e.Value, Source: "memory:" + k}
	if e.Tainted {
		r.Untrusted = true
		w.markUntrusted("memory:" + k)
	}
	return r
}
