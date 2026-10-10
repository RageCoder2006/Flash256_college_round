// Package api serves the dashboard: read-only views over saved traces and reports,
// guard control, and a small run manager that launches campaign/validate/hunt subprocesses.
package api

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/41vi4p/agentbreak/core/internal/audit"
	"github.com/41vi4p/agentbreak/core/internal/guard"
	"github.com/41vi4p/agentbreak/core/internal/scenario"
	"github.com/41vi4p/agentbreak/core/internal/trace"
)

type Config struct {
	OutDir       string
	ScenarioPath string
	SeedsPath    string
	SandboxBin   string
	GuardURL     string
	Exe          string // path to this binary, used to launch runs
	Offline      bool   // default for launched runs
}

type Server struct {
	cfg  Config
	mu   sync.Mutex
	runs map[string]*Run
	cur  string
}

func New(cfg Config) *Server { return &Server{cfg: cfg, runs: map[string]*Run{}} }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/summary", s.summary)
	mux.HandleFunc("GET /api/traces", s.traces)
	mux.HandleFunc("GET /api/traces/{id}", s.traceByID)
	mux.HandleFunc("GET /api/pairs", s.pairs)
	mux.HandleFunc("GET /api/audit", s.auditHandler)
	mux.HandleFunc("GET /api/advisories", func(w http.ResponseWriter, r *http.Request) {
		v := readJSONFile(filepath.Join(s.cfg.OutDir, "advisories.json"))
		if v == nil {
			v = []any{}
		}
		writeJSON(w, v)
	})
	mux.HandleFunc("GET /api/guard", s.guardStatus)
	mux.HandleFunc("POST /api/guard/mode", s.guardMode)
	mux.HandleFunc("GET /api/runs", s.listRuns)
	mux.HandleFunc("POST /api/runs", s.startRun)
	mux.HandleFunc("GET /api/runs/{id}/stream", s.streamRun)
	return cors(mux)
}

// cors lets the local dashboard (and only it) call the API from the browser.
func cors(next http.Handler) http.Handler {
	allowed := map[string]bool{"http://localhost:3000": true, "http://127.0.0.1:3000": true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); allowed[o] {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Headers", "content-type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func readJSONFile(path string) any {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var v any
	if json.Unmarshal(b, &v) != nil {
		return nil
	}
	return v
}

func (s *Server) loadTraces() []*trace.Trace {
	matches, _ := filepath.Glob(filepath.Join(s.cfg.OutDir, "traces", "*.json"))
	var out []*trace.Trace
	for _, m := range matches {
		if tr, err := trace.Load(m); err == nil {
			out = append(out, tr)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	trs := s.loadTraces()
	writeJSON(w, map[string]any{
		"validation":   readJSONFile(filepath.Join(s.cfg.OutDir, "validation.json")),
		"campaign":     readJSONFile(filepath.Join(s.cfg.OutDir, "report.json")),
		"hunt":         readJSONFile(filepath.Join(s.cfg.OutDir, "hunt.json")),
		"trace_count":  len(trs),
		"scenario":     s.cfg.ScenarioPath,
		"default_offl": s.cfg.Offline,
	})
}

type traceSummary struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Guard     string    `json:"guard_mode"`
	Model     string    `json:"model"`
	Technique string    `json:"technique,omitempty"`
	SeedID    string    `json:"seed_id,omitempty"`
	Surface   string    `json:"surface,omitempty"`
	Operator  string    `json:"operator,omitempty"`
	Success   bool      `json:"success"`
	Progress  int       `json:"progress"`
	Findings  int       `json:"findings"`
	Started   time.Time `json:"started_at"`
	Steps     int       `json:"steps"`
}

func (s *Server) traces(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	var out []traceSummary
	for _, tr := range s.loadTraces() {
		if kind != "" && tr.Kind != kind {
			continue
		}
		ts := traceSummary{ID: tr.TraceID, Kind: tr.Kind, Guard: tr.GuardMode, Model: tr.Model, Success: tr.Success,
			Progress: tr.Progress, Findings: len(tr.Findings), Started: tr.StartedAt, Steps: len(tr.Steps)}
		if tr.Attack != nil {
			ts.Technique, ts.SeedID, ts.Surface, ts.Operator = tr.Attack.Technique, tr.Attack.SeedID, tr.Attack.Surface, tr.Attack.Encoding
		}
		out = append(out, ts)
		if len(out) >= 500 {
			break
		}
	}
	writeJSON(w, out)
}

func (s *Server) traceByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if strings.ContainsAny(id, "/\\.") {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	tr, err := trace.Load(filepath.Join(s.cfg.OutDir, "traces", id+".json"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"trace": tr, "strip": Strip(tr), "chain_ok": tr.Verify() == nil, "head": tr.HeadHash()})
}

type pairView struct {
	Key       string  `json:"key"`
	SeedID    string  `json:"seed_id"`
	Technique string  `json:"technique"`
	Surface   string  `json:"surface"`
	Operator  string  `json:"operator"`
	Off       *Side   `json:"off,omitempty"`
	Enforce   *Side   `json:"enforce,omitempty"`
	Payload   string  `json:"payload"`
	At        float64 `json:"-"`
}

type Side struct {
	TraceID string `json:"trace_id"`
	Success bool   `json:"success"`
	Strip   []Node `json:"strip"`
}

// pairs groups attack traces by identical payload+surface so an exploit and its guarded replay line up.
func (s *Server) pairs(w http.ResponseWriter, r *http.Request) {
	groups := map[string]*pairView{}
	var order []string
	for _, tr := range s.loadTraces() { // newest first
		if tr.Kind != "attack" || tr.Attack == nil {
			continue
		}
		h := sha256.Sum256([]byte(tr.Attack.Payload))
		key := tr.Attack.SeedID + "|" + tr.Attack.Surface + "|" + hex.EncodeToString(h[:4])
		g := groups[key]
		if g == nil {
			g = &pairView{Key: key, SeedID: tr.Attack.SeedID, Technique: tr.Attack.Technique, Surface: tr.Attack.Surface, Operator: tr.Attack.Encoding, Payload: tr.Attack.Payload}
			groups[key] = g
			order = append(order, key)
		}
		side := &Side{TraceID: tr.TraceID, Success: tr.Success, Strip: Strip(tr)}
		switch tr.GuardMode {
		case "off":
			if g.Off == nil {
				g.Off = side
			}
		case "enforce":
			if g.Enforce == nil {
				g.Enforce = side
			}
		}
	}
	out := []*pairView{}
	for _, k := range order {
		g := groups[k]
		if g.Off != nil && g.Off.Success { // only exploits that worked unguarded
			out = append(out, g)
		}
	}
	writeJSON(w, out)
}

func (s *Server) auditHandler(w http.ResponseWriter, r *http.Request) {
	sc, err := scenario.Load(s.cfg.ScenarioPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"scenario": map[string]any{"id": sc.ID, "name": sc.Name, "description": sc.Description, "tools": sc.Tools}, "findings": audit.Static(sc)})
}

func (s *Server) guardStatus(w http.ResponseWriter, r *http.Request) {
	if s.cfg.GuardURL == "" {
		writeJSON(w, map[string]any{"reachable": false, "reason": "no guard URL configured"})
		return
	}
	g := guard.New(s.cfg.GuardURL)
	m, err := g.Metrics(r.Context())
	if err != nil {
		writeJSON(w, map[string]any{"reachable": false, "reason": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"reachable": true, "mode": m.Mode, "metrics": m})
}

func (s *Server) guardMode(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Mode string `json:"mode"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&b) != nil || (b.Mode != "off" && b.Mode != "monitor" && b.Mode != "enforce") {
		http.Error(w, "mode must be off|monitor|enforce", http.StatusBadRequest)
		return
	}
	if err := guard.New(s.cfg.GuardURL).SetMode(r.Context(), b.Mode); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]string{"mode": b.Mode})
}

// ---- run manager ----

type Run struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	Status  string    `json:"status"` // running | done | failed
	Started time.Time `json:"started_at"`
	mu      sync.Mutex
	lines   []string
}

func (r *Run) add(l string) {
	r.mu.Lock()
	r.lines = append(r.lines, l)
	r.mu.Unlock()
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []*Run{}
	for _, run := range s.runs {
		out = append(out, run)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.After(out[j].Started) })
	writeJSON(w, out)
}

type startReq struct {
	Kind       string `json:"kind"` // campaign | validate | hunt
	Offline    *bool  `json:"offline"`
	Budget     int    `json:"budget"`
	VsDefense  bool   `json:"vs_defense"`
	GuardMode  string `json:"guard"`
	Regression bool   `json:"regress"`
}

func (s *Server) startRun(w http.ResponseWriter, r *http.Request) {
	var req startReq
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req) != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	args := []string{req.Kind, "-scenario", s.cfg.ScenarioPath, "-out", s.cfg.OutDir}
	if s.cfg.SeedsPath != "" {
		args = append(args, "-seeds", s.cfg.SeedsPath)
	}
	if s.cfg.SandboxBin != "" {
		args = append(args, "-sandbox", s.cfg.SandboxBin)
	}
	offline := s.cfg.Offline
	if req.Offline != nil {
		offline = *req.Offline
	}
	if offline {
		args = append(args, "-offline")
	}
	if s.cfg.GuardURL != "" {
		args = append(args, "-guard-url", s.cfg.GuardURL)
	}
	switch req.Kind {
	case "campaign":
		if req.GuardMode == "monitor" || req.GuardMode == "enforce" {
			args = append(args, "-guard", req.GuardMode)
		}
		if req.Regression {
			args = append(args, "-regress")
		}
	case "validate":
	case "hunt":
		b := req.Budget
		if b < 1 || b > 500 {
			b = 40
		}
		args = append(args, "-budget", fmt.Sprint(b))
		if req.VsDefense {
			args = append(args, "-vs-defense")
		}
	default:
		http.Error(w, "kind must be campaign|validate|hunt", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if s.cur != "" {
		if c := s.runs[s.cur]; c != nil && c.Status == "running" {
			s.mu.Unlock()
			http.Error(w, "a run is already in progress", http.StatusConflict)
			return
		}
	}
	run := &Run{ID: fmt.Sprintf("run-%d", time.Now().UnixNano()/1e6), Kind: req.Kind, Status: "running", Started: time.Now()}
	s.runs[run.ID], s.cur = run, run.ID
	s.mu.Unlock()
	go s.exec(run, args)
	writeJSON(w, run)
}

func (s *Server) exec(run *Run, args []string) {
	run.add("$ agentbreak " + strings.Join(args, " "))
	cmd := exec.Command(s.cfg.Exe, args...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		run.add("error: " + err.Error())
		run.Status = "failed"
		return
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		run.add("error: " + err.Error())
		run.Status = "failed"
		return
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		run.add(sc.Text())
	}
	status := "done"
	if err := cmd.Wait(); err != nil {
		run.add("exit: " + err.Error())
		status = "failed"
	}
	run.mu.Lock()
	run.Status = status
	run.mu.Unlock()
}

func (s *Server) streamRun(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	run := s.runs[r.PathValue("id")]
	s.mu.Unlock()
	if run == nil {
		http.Error(w, "unknown run", http.StatusNotFound)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "text/event-stream")
	w.Header().Set("cache-control", "no-cache")
	sent := 0
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		run.mu.Lock()
		batch := append([]string(nil), run.lines[sent:]...)
		status := run.Status
		run.mu.Unlock()
		for _, l := range batch {
			b, _ := json.Marshal(l)
			fmt.Fprintf(w, "event: line\ndata: %s\n\n", b)
		}
		sent += len(batch)
		if status != "running" && len(batch) == 0 {
			fmt.Fprintf(w, "event: end\ndata: %q\n\n", status)
			fl.Flush()
			return
		}
		fl.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
		}
	}
}
