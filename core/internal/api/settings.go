package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/41vi4p/avhsol/core/internal/cliagent"
	"github.com/41vi4p/avhsol/core/internal/guard"
	"github.com/41vi4p/avhsol/core/internal/scenario"
)

// Settings are the non-secret defaults an administrator can change from the dashboard. They are stored as JSON next to the
// run output. Secrets (the model key, API tokens, database passwords) are never settings: they come from the environment.
type Settings struct {
	Scenario         string   `json:"scenario"`   // path under scenarios/
	Seeds            string   `json:"seeds"`      // path under seeds/
	Target           string   `json:"target"`     // path under targets/, "" = simulated-tool harness
	Isolation        string   `json:"isolation"`  // landlock | gvisor
	GuardMode        string   `json:"guard_mode"` // off | monitor | enforce
	Offline          bool     `json:"offline"`    // default for launched runs: simulated model
	Repeats          int      `json:"repeats"`
	Budget           int      `json:"budget"`
	ReportSkeleton   string   `json:"report_skeleton"`
	ReportTitle      string   `json:"report_title"`
	Classification   string   `json:"classification"`
	RefreshSec       int      `json:"refresh_sec"`      // Status page update interval
	IntelSyncHours   int      `json:"intel_sync_hours"` // 0 = manual only (informational: the scheduler is not built)
	DisabledDefenses []string `json:"disabled_defenses"`
	UpdatedBy        string   `json:"updated_by,omitempty"`
	UpdatedAt        string   `json:"updated_at,omitempty"`
}

type settingsStore struct {
	mu   sync.Mutex
	path string
	v    Settings
	ok   bool
}

func newSettingsStore(path string) *settingsStore { return &settingsStore{path: path} }

func defaultSettings(cfg Config) Settings {
	return Settings{Scenario: cfg.ScenarioPath, Seeds: cfg.SeedsPath, Isolation: cliagent.IsolationLandlock, GuardMode: "off", Offline: cfg.Offline,
		Repeats: 1, Budget: 40, ReportSkeleton: "security-report", Classification: "CONFIDENTIAL", RefreshSec: 2}
}

func (st *settingsStore) get(cfg Config) Settings {
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.ok {
		st.v = defaultSettings(cfg)
		if b, err := os.ReadFile(st.path); err == nil {
			var f Settings
			if json.Unmarshal(b, &f) == nil {
				st.v = overlay(st.v, f)
			}
		}
		st.ok = true
	}
	return st.v
}

// overlay applies the fields a file sets over the defaults, so a settings file from an older version still loads.
func overlay(base, f Settings) Settings {
	if f.Scenario != "" {
		base.Scenario = f.Scenario
	}
	if f.Seeds != "" {
		base.Seeds = f.Seeds
	}
	base.Target = f.Target
	if f.Isolation != "" {
		base.Isolation = f.Isolation
	}
	if f.GuardMode != "" {
		base.GuardMode = f.GuardMode
	}
	base.Offline = f.Offline
	if f.Repeats > 0 {
		base.Repeats = f.Repeats
	}
	if f.Budget > 0 {
		base.Budget = f.Budget
	}
	if f.ReportSkeleton != "" {
		base.ReportSkeleton = f.ReportSkeleton
	}
	base.ReportTitle, base.Classification = f.ReportTitle, orDefault(f.Classification, base.Classification)
	if f.RefreshSec > 0 {
		base.RefreshSec = f.RefreshSec
	}
	base.IntelSyncHours, base.DisabledDefenses = f.IntelSyncHours, f.DisabledDefenses
	base.UpdatedBy, base.UpdatedAt = f.UpdatedBy, f.UpdatedAt
	return base
}

func orDefault(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (st *settingsStore) put(v Settings) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.MkdirAll(filepath.Dir(st.path), 0o755); err != nil {
		return err
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, st.path); err != nil {
		return err
	}
	st.v, st.ok = v, true
	return nil
}

// CatalogItem is one selectable scenario, seed file or target.
type CatalogItem struct {
	Path        string `json:"path"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Kind        string `json:"kind,omitempty"` // targets: cli | mcp | http
	Sandbox     bool   `json:"sandbox,omitempty"`
}

// Catalog lists what can be chosen: files in scenarios/, seeds/ and targets/ next to the configured scenario's repository root.
func (s *Server) catalog() map[string][]CatalogItem {
	root := s.repoRoot()
	out := map[string][]CatalogItem{"scenarios": {}, "seeds": {}, "targets": {}}
	for _, dir := range []string{"scenarios", "seeds", "targets"} {
		files, _ := filepath.Glob(filepath.Join(root, dir, "*.yaml"))
		sort.Strings(files)
		for _, f := range files {
			rel, _ := filepath.Rel(root, f)
			it := CatalogItem{Path: rel, Name: strings.TrimSuffix(filepath.Base(f), ".yaml")}
			switch dir {
			case "scenarios":
				if sc, err := scenario.Load(f); err == nil {
					it.Name, it.Description, it.Sandbox = sc.Name, clipDesc(sc.Description), sc.Sandbox
				} else {
					continue
				}
			case "targets":
				if t, err := cliagent.Load(f); err == nil {
					it.Name, it.Kind = t.Name, t.Kind
				} else {
					continue
				}
			}
			out[dir] = append(out[dir], it)
		}
	}
	return out
}

func clipDesc(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:199] + "…"
	}
	return s
}

// repoRoot is the directory that holds scenarios/, seeds/ and targets/ (the parent of the configured scenario's directory).
func (s *Server) repoRoot() string {
	if s.cfg.ScenarioPath == "" {
		return "."
	}
	abs, err := filepath.Abs(s.cfg.ScenarioPath)
	if err != nil {
		return "."
	}
	return filepath.Dir(filepath.Dir(abs))
}

// inCatalog returns the repository-relative path if it names a catalogued file, so a request can never point the launcher at an arbitrary path.
func (s *Server) inCatalog(kind, p string) (string, bool) {
	if p == "" {
		return "", true
	}
	root := s.repoRoot()
	abs := p
	if !filepath.IsAbs(p) {
		abs = filepath.Join(root, p)
	}
	abs = filepath.Clean(abs)
	for _, it := range s.catalog()[kind] {
		if filepath.Join(root, it.Path) == abs {
			return abs, true
		}
	}
	return "", false
}

func (s *Server) validateSettings(v *Settings) error {
	for _, c := range []struct {
		kind string
		p    *string
	}{{"scenarios", &v.Scenario}, {"seeds", &v.Seeds}, {"targets", &v.Target}} {
		abs, ok := s.inCatalog(c.kind, *c.p)
		if !ok {
			return fmt.Errorf("%s %q is not a file in the %s directory", strings.TrimSuffix(c.kind, "s"), *c.p, c.kind)
		}
		*c.p = abs
	}
	if v.Isolation != cliagent.IsolationLandlock && v.Isolation != cliagent.IsolationGVisor {
		return fmt.Errorf("isolation must be landlock or gvisor")
	}
	if v.GuardMode != "off" && v.GuardMode != "monitor" && v.GuardMode != "enforce" {
		return fmt.Errorf("guard_mode must be off, monitor or enforce")
	}
	if v.Repeats < 1 || v.Repeats > 20 || v.Budget < 1 || v.Budget > 500 {
		return fmt.Errorf("repeats must be 1-20 and budget 1-500")
	}
	if v.RefreshSec < 1 || v.RefreshSec > 60 || v.IntelSyncHours < 0 || v.IntelSyncHours > 24*30 {
		return fmt.Errorf("refresh_sec must be 1-60 and intel_sync_hours 0-720")
	}
	if len(v.ReportTitle) > 120 || len(v.Classification) > 40 {
		return fmt.Errorf("report title or classification too long")
	}
	known := map[string]bool{}
	for _, d := range guard.AllDefenses {
		known[d] = true
	}
	for _, d := range v.DisabledDefenses {
		if !known[d] {
			return fmt.Errorf("unknown defense %q", d)
		}
	}
	return nil
}

func (s *Server) settingsRoutes(mux *http.ServeMux) {
	h := s.handle
	h(mux, "GET /api/catalog", RoleViewer, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.catalog()) })
	h(mux, "GET /api/settings", RoleOperator, func(w http.ResponseWriter, r *http.Request) {
		v := s.set.get(s.cfg)
		root := s.repoRoot()
		for _, p := range []*string{&v.Scenario, &v.Seeds, &v.Target} { // show repository-relative paths
			if rel, err := filepath.Rel(root, *p); err == nil && *p != "" && !strings.HasPrefix(rel, "..") {
				*p = rel
			}
		}
		writeJSON(w, map[string]any{"settings": v, "catalog": s.catalog(), "defenses": guard.AllDefenses, "secrets_note": "The model key, API tokens and database passwords are never settings; they are read from the environment."})
	})
	h(mux, "PUT /api/settings", RoleAdmin, func(w http.ResponseWriter, r *http.Request) {
		v := s.set.get(s.cfg)
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&v) != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if err := s.validateSettings(&v); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		who := callerOf(r)
		v.UpdatedBy, v.UpdatedAt = who.ID, time.Now().UTC().Format(time.RFC3339)
		if err := s.set.put(v); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, v)
	})
	// Guard defenses: which of D1-D7 are enforced when the guard is on. Pushes the policy for the configured scenario.
	h(mux, "GET /api/guard/policy", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		v := s.set.get(s.cfg)
		off := map[string]bool{}
		for _, d := range v.DisabledDefenses {
			off[d] = true
		}
		var on []string
		for _, d := range guard.AllDefenses {
			if !off[d] {
				on = append(on, d)
			}
		}
		writeJSON(w, map[string]any{"all": guard.AllDefenses, "enabled": on})
	})
	h(mux, "POST /api/guard/policy", RoleOperator, func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Enabled []string `json:"enabled"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&b) != nil {
			http.Error(w, "send {enabled: [\"D1\", ...]}", http.StatusBadRequest)
			return
		}
		on := map[string]bool{}
		for _, d := range b.Enabled {
			on[d] = true
		}
		var off []string
		for _, d := range guard.AllDefenses {
			if !on[d] {
				off = append(off, d)
			}
		}
		for d := range on {
			ok := false
			for _, k := range guard.AllDefenses {
				ok = ok || k == d
			}
			if !ok {
				http.Error(w, "unknown defense "+d, http.StatusBadRequest)
				return
			}
		}
		sc, err := scenario.Load(s.cfg.ScenarioPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if s.cfg.GuardURL == "" {
			http.Error(w, "no guard configured", http.StatusServiceUnavailable)
			return
		}
		if err := guard.New(s.cfg.GuardURL).PushPolicy(r.Context(), guard.PolicyFromScenario(sc, b.Enabled)); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		v := s.set.get(s.cfg)
		v.DisabledDefenses = off
		_ = s.set.put(v)
		writeJSON(w, map[string]any{"enabled": b.Enabled, "disabled": off})
	})
	h(mux, "POST /api/llm/test", RoleOperator, func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		writeJSON(w, s.checkLLM(ctx, true))
	})
	h(mux, "POST /api/graph/reset", RoleAdmin, func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Confirm string `json:"confirm"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&b) != nil || b.Confirm != "RESET" {
			http.Error(w, `send {"confirm":"RESET"}: this deletes every node and vector`, http.StatusBadRequest)
			return
		}
		if !s.needGraph(w) {
			return
		}
		if err := s.cfg.Graph.Reset(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"reset": true})
	})
	h(mux, "POST /api/runs/{id}/cancel", RoleOperator, func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		run := s.runs[r.PathValue("id")]
		s.mu.Unlock()
		if run == nil {
			http.NotFound(w, r)
			return
		}
		if !run.cancel() {
			http.Error(w, "that run is not running", http.StatusConflict)
			return
		}
		writeJSON(w, map[string]any{"canceling": true})
	})
}

// cancel interrupts the run's process group, then kills it if it has not stopped after a grace period.
func (r *Run) cancel() bool {
	r.mu.Lock()
	if r.Status != "running" || r.cmd == nil || r.cmd.Process == nil {
		r.mu.Unlock()
		return false
	}
	r.Canceled = true
	pid := r.cmd.Process.Pid
	r.mu.Unlock()
	r.add("-- cancel requested: sending interrupt --")
	_ = killGroup(pid, false)
	go func() {
		time.Sleep(8 * time.Second)
		r.mu.Lock()
		still := r.Status == "running"
		r.mu.Unlock()
		if still {
			r.add("-- still running after 8 s: killing --")
			_ = killGroup(pid, true)
		}
	}()
	return true
}
