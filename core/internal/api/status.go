package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/41vi4p/avhsol/core/internal/home"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/41vi4p/avhsol/core/internal/brand"
	"github.com/41vi4p/avhsol/core/internal/cliagent"
	"github.com/41vi4p/avhsol/core/internal/export"
	"github.com/41vi4p/avhsol/core/internal/graph"
	"github.com/41vi4p/avhsol/core/internal/guard"
	"github.com/41vi4p/avhsol/core/internal/intel"
	"github.com/41vi4p/avhsol/core/internal/sign"
	"github.com/41vi4p/avhsol/core/internal/sysmon"
)

// Health is one line of the environment checklist on the Status page. State is ok, warn, bad or off ("not configured").
type Health struct {
	ID        string  `json:"id"`
	Label     string  `json:"label"`
	State     string  `json:"state"`
	Detail    string  `json:"detail,omitempty"`
	LatencyMs float64 `json:"latency_ms,omitempty"`
}

type healthCache struct {
	mu    sync.Mutex
	at    time.Time
	list  []Health
	llm   Health
	llmAt time.Time
}

// sampler returns the host sampler, starting it on first use.
func (s *Server) sampler() *sysmon.Sampler {
	s.monOnce.Do(func() {
		s.mon = sysmon.New(sysmon.Config{Paths: []string{s.cfg.OutDir}, RunPID: s.currentRunPID, Limits: s.sandboxLimits})
		s.mon.Start()
	})
	return s.mon
}

func (s *Server) currentRunPID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.runs[s.cur]
	if run == nil {
		return 0
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.Status == "running" && run.cmd != nil && run.cmd.Process != nil {
		return run.cmd.Process.Pid
	}
	return 0
}

// sandboxLimits are the ceilings configured for launched runs. For Landlock the memory limit is the truth: none.
func (s *Server) sandboxLimits() sysmon.Limits {
	v := s.set.get(s.cfg)
	if v.Isolation == cliagent.IsolationGVisor {
		return sysmon.Limits{Isolation: "gvisor", MaxProcs: 512, MemoryBytes: 2 << 30, Note: "docker --memory 2g, --cpus 2, --pids-limit 512, no network"}
	}
	return sysmon.Limits{Isolation: "landlock", MaxProcs: 512, MemoryBytes: 0, CPUSeconds: 0,
		Note: "Landlock + seccomp: process count and CPU time are limited; memory is NOT limited for command-line agents"}
}

func (s *Server) checkLLM(ctx context.Context, force bool) Health {
	s.hc.mu.Lock()
	defer s.hc.mu.Unlock()
	if !force && time.Since(s.hc.llmAt) < 20*time.Second && s.hc.llm.ID != "" {
		return s.hc.llm
	}
	h := Health{ID: "llm", Label: "Model endpoint"}
	switch {
	case s.cfg.LLM == nil:
		h.State, h.Detail = "off", "not configured: set AVHSOL_LLM_BASE_URL and AVHSOL_LLM_MODEL"
	default:
		u := strings.TrimRight(s.cfg.LLM.BaseURL, "/") + "/models"
		req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		if s.cfg.LLM.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+s.cfg.LLM.APIKey)
		}
		t0 := time.Now()
		res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		h.LatencyMs = float64(time.Since(t0).Microseconds()) / 1000
		host := ""
		if pu, e := url.Parse(s.cfg.LLM.BaseURL); e == nil {
			host = pu.Host
		}
		if err != nil {
			h.State, h.Detail = "bad", "cannot reach "+host
		} else {
			b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
			res.Body.Close()
			if res.StatusCode/100 != 2 {
				h.State, h.Detail = "bad", fmt.Sprintf("%s answered HTTP %d", host, res.StatusCode)
			} else {
				h.State = "ok"
				var m struct {
					Data []struct{ ID string } `json:"data"`
				}
				_ = json.Unmarshal(b, &m)
				h.Detail = fmt.Sprintf("%s · model %s · %d model(s) listed", host, s.cfg.LLM.Model, len(m.Data))
				found := len(m.Data) == 0
				for _, d := range m.Data {
					found = found || d.ID == s.cfg.LLM.Model
				}
				if !found {
					h.State, h.Detail = "warn", host+": the configured model is not in the endpoint's list"
				}
			}
		}
	}
	s.hc.llm, s.hc.llmAt = h, time.Now()
	return h
}

// health runs the environment checks (cached for 6 s; the model endpoint for 20 s so the user's server is not polled every tick).
func (s *Server) health(ctx context.Context) []Health {
	s.hc.mu.Lock()
	if time.Since(s.hc.at) < 6*time.Second && len(s.hc.list) > 0 {
		l := append([]Health(nil), s.hc.list...)
		s.hc.mu.Unlock()
		for i := range l {
			if l[i].ID == "llm" {
				l[i] = s.checkLLM(ctx, false)
			}
		}
		return l
	}
	s.hc.mu.Unlock()
	var out []Health
	add := func(h Health) { out = append(out, h) }
	add(Health{ID: "api", Label: "API", State: "ok", Detail: fmt.Sprintf("up %s", time.Since(s.started).Round(time.Second))})
	// guard
	if s.cfg.GuardURL == "" {
		add(Health{ID: "guard", Label: "Guard proxy", State: "off", Detail: "no guard URL configured"})
	} else {
		t0 := time.Now()
		m, err := guard.New(s.cfg.GuardURL).Metrics(ctx)
		if err != nil {
			add(Health{ID: "guard", Label: "Guard proxy", State: "bad", Detail: "not reachable"})
		} else {
			st := "ok"
			if m.Mode == "off" {
				st = "warn"
			}
			add(Health{ID: "guard", Label: "Guard proxy", State: st, Detail: "mode " + m.Mode, LatencyMs: float64(time.Since(t0).Microseconds()) / 1000})
		}
	}
	// neo4j + qdrant
	if s.cfg.Graph == nil {
		add(Health{ID: "neo4j", Label: "Neo4j graph", State: "off", Detail: "serve was started without -graph"})
		add(Health{ID: "qdrant", Label: "Qdrant vectors", State: "off", Detail: "serve was started without -graph"})
	} else {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		t0 := time.Now()
		rows, err := s.cfg.Graph.Stats(cctx)
		cancel()
		if err != nil {
			add(Health{ID: "neo4j", Label: "Neo4j graph", State: "bad", Detail: "query failed"})
		} else {
			n := 0
			for _, r := range rows {
				switch v := r["n"].(type) {
				case int64:
					n += int(v)
				}
			}
			add(Health{ID: "neo4j", Label: "Neo4j graph", State: "ok", Detail: fmt.Sprintf("%d nodes", n), LatencyMs: float64(time.Since(t0).Microseconds()) / 1000})
		}
		if s.cfg.Index == nil {
			add(Health{ID: "qdrant", Label: "Qdrant vectors", State: "off", Detail: "no vector index"})
		} else {
			cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			t0 := time.Now()
			err := s.cfg.Index.Q.Health(cctx)
			cancel()
			if err != nil {
				add(Health{ID: "qdrant", Label: "Qdrant vectors", State: "bad", Detail: "not ready"})
			} else {
				add(Health{ID: "qdrant", Label: "Qdrant vectors", State: "ok", Detail: "ready · " + s.cfg.Index.Emb.Name(), LatencyMs: float64(time.Since(t0).Microseconds()) / 1000})
			}
		}
	}
	// sandbox backends
	if _, err := os.Stat(s.cfg.SandboxBin); err != nil {
		add(Health{ID: "landlock", Label: "Sandbox (Landlock)", State: "bad", Detail: "avhsol-sandbox binary not found"})
	} else {
		add(Health{ID: "landlock", Label: "Sandbox (Landlock)", State: "ok", Detail: "avhsol-sandbox present"})
	}
	if err := cliagent.GVisorAvailable(ctx); err != nil {
		add(Health{ID: "gvisor", Label: "Sandbox (gVisor)", State: "off", Detail: shortErr(err)})
	} else {
		add(Health{ID: "gvisor", Label: "Sandbox (gVisor)", State: "ok", Detail: "docker + runsc available"})
	}
	if export.PDFAvailable() {
		add(Health{ID: "chrome", Label: "PDF export (Chrome)", State: "ok", Detail: "Chrome/Chromium found"})
	} else {
		add(Health{ID: "chrome", Label: "PDF export (Chrome)", State: "warn", Detail: "not found; set AVHSOL_CHROME for PDF reports"})
	}
	key := graph.Setting("AVHSOL_SIGNING_KEY", "", home.SigningKey())
	if _, err := os.Stat(key); err != nil {
		add(Health{ID: "signing", Label: "Trace signing key", State: "warn", Detail: "none; run avhsol keygen"})
	} else {
		d, st := "present", "ok"
		if sg, e1 := sign.LoadSigner(key); e1 == nil {
			if pub, e2 := sign.LoadPublic(key + ".pub"); e2 != nil {
				d, st = "private key present, public key missing or unreadable", "warn"
			} else if sign.KeyID(pub) != sg.ID {
				d, st = "the public key does not match the private key: signatures will fail to verify", "bad"
			} else {
				d = "key " + sg.ID + ", public key matches"
			}
		}
		add(Health{ID: "signing", Label: "Trace signing key", State: st, Detail: d})
	}
	if s.cfg.AuditPath != "" {
		if n, err := VerifyAuditLog(s.cfg.AuditPath); err != nil {
			add(Health{ID: "audit", Label: "Audit log", State: "bad", Detail: "hash chain broken: " + shortErr(err)})
		} else {
			add(Health{ID: "audit", Label: "Audit log", State: "ok", Detail: fmt.Sprintf("%d entries, chain intact", n)})
		}
	}
	if st, err := intel.Open(intel.Dir()); err == nil {
		d := "empty: run avhsol intel sync"
		state := "warn"
		if n := st.Count(); n > 0 {
			state, d = "ok", fmt.Sprintf("%d records", n)
			var newest time.Time
			for _, src := range st.State.Sources {
				if t, e := time.Parse(time.RFC3339, src.LastSync); e == nil && t.After(newest) {
					newest = t
				}
			}
			if !newest.IsZero() {
				d += fmt.Sprintf(" · synced %s ago", time.Since(newest).Round(time.Minute))
				if time.Since(newest) > 14*24*time.Hour {
					state = "warn"
				}
			}
		}
		add(Health{ID: "intel", Label: "Threat-intel cache", State: state, Detail: d})
	}
	s.hc.mu.Lock()
	s.hc.at, s.hc.list = time.Now(), out
	s.hc.mu.Unlock()
	out = append([]Health{}, out...)
	// the model endpoint check sits in the list position after neo4j/qdrant for display
	llm := s.checkLLM(ctx, false)
	out = append(out[:3:3], append([]Health{llm}, out[3:]...)...)
	s.hc.mu.Lock()
	s.hc.list = append([]Health(nil), out...)
	s.hc.mu.Unlock()
	return out
}

func shortErr(err error) string {
	m := err.Error()
	if len(m) > 140 {
		m = m[:139] + "…"
	}
	return m
}

type runInfo struct {
	ID      string   `json:"id,omitempty"`
	Kind    string   `json:"kind,omitempty"`
	Status  string   `json:"status"`
	Started string   `json:"started_at,omitempty"`
	Elapsed float64  `json:"elapsed_sec,omitempty"`
	Tail    []string `json:"tail,omitempty"`
	Lines   int      `json:"lines,omitempty"`
}

func (s *Server) runInfo() runInfo {
	s.mu.Lock()
	run := s.runs[s.cur]
	s.mu.Unlock()
	if run == nil {
		return runInfo{Status: "idle"}
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	ri := runInfo{ID: run.ID, Kind: run.Kind, Status: run.Status, Started: run.Started.Format(time.RFC3339), Lines: len(run.lines)}
	end := time.Now()
	if run.Ended != nil {
		end = *run.Ended
	}
	ri.Elapsed = end.Sub(run.Started).Seconds()
	from := len(run.lines) - 14
	if from < 0 {
		from = 0
	}
	ri.Tail = append([]string(nil), run.lines[from:]...)
	return ri
}

type traceStats struct {
	Total     int `json:"total"`
	Attacks   int `json:"attacks"`
	Benign    int `json:"benign"`
	Valid     int `json:"valid_attacks"`
	Exploits  int `json:"exploits"`
	Errored   int `json:"errored"`
	Simulated int `json:"simulated"`
}

var (
	tsMu   sync.Mutex
	tsAt   time.Time
	tsLast traceStats
)

func (s *Server) traceStats() traceStats {
	tsMu.Lock()
	defer tsMu.Unlock()
	if time.Since(tsAt) < 4*time.Second {
		return tsLast
	}
	var t traceStats
	for _, tr := range s.loadTraces() {
		t.Total++
		if tr.Kind == "benign" {
			t.Benign++
			continue
		}
		t.Attacks++
		if tr.Model == "offline-simulated" {
			t.Simulated++
		}
		if tr.Error != "" && !tr.Success {
			t.Errored++
			continue
		}
		t.Valid++
		if tr.Success {
			t.Exploits++
		}
	}
	tsAt, tsLast = time.Now(), t
	return t
}

func (s *Server) statusJSON(ctx context.Context) map[string]any {
	snap := s.sampler().Latest()
	set := s.set.get(s.cfg)
	env := map[string]any{"scenario": baseOrEmpty(set.Scenario), "seeds": baseOrEmpty(set.Seeds), "target": baseOrEmpty(set.Target), "isolation": set.Isolation,
		"guard_default": set.GuardMode, "offline_default": set.Offline, "graph": s.cfg.Graph != nil, "go": runtime.Version(), "os": runtime.GOOS + "/" + runtime.GOARCH,
		"grafana": os.Getenv("AVHSOL_GRAFANA_URL"), "refresh_sec": set.RefreshSec}
	if s.cfg.LLM != nil {
		env["model"] = s.cfg.LLM.Model
	}
	out := map[string]any{"at": time.Now().UnixMilli(), "sys": snap, "health": s.health(ctx), "run": s.runInfo(), "traces": s.traceStats(), "env": env}
	if s.cfg.GuardURL != "" {
		if m, err := guard.New(s.cfg.GuardURL).Metrics(ctx); err == nil {
			out["guard"] = m
		}
	}
	return out
}

// histPoint is one compact point of history for the charts.
type histPoint struct {
	At      int64   `json:"t"`
	CPU     float64 `json:"cpu"`
	Mem     float64 `json:"mem"`  // used percent
	Swap    float64 `json:"swap"` // used percent
	Load1   float64 `json:"load1"`
	NetRx   float64 `json:"rx"`
	NetTx   float64 `json:"tx"`
	DiskR   float64 `json:"dr"`
	DiskW   float64 `json:"dw"`
	SbCPU   float64 `json:"sb_cpu"`
	SbRSS   uint64  `json:"sb_rss"`
	SbProcs int     `json:"sb_procs"`
	PSICPU  float64 `json:"psi_cpu"`
	PSIMem  float64 `json:"psi_mem"`
	PSIIO   float64 `json:"psi_io"`
}

func compact(s sysmon.Snapshot) histPoint {
	h := s.Host
	p := histPoint{At: h.At, CPU: h.CPU, Load1: h.Load[0], NetRx: h.NetRx, NetTx: h.NetTx, DiskR: h.DiskRead, DiskW: h.DiskWrite,
		SbCPU: s.Sandbox.CPU, SbRSS: s.Sandbox.RSSBytes, SbProcs: s.Sandbox.Procs, PSICPU: h.PSI.CPU, PSIMem: h.PSI.Mem, PSIIO: h.PSI.IO}
	if h.Mem.TotalKB > 0 {
		p.Mem = 100 * float64(h.Mem.UsedKB) / float64(h.Mem.TotalKB)
	}
	if h.Mem.SwapTotalKB > 0 {
		p.Swap = 100 * float64(h.Mem.SwapUsedKB) / float64(h.Mem.SwapTotalKB)
	}
	return p
}

func (s *Server) statusRoutes(mux *http.ServeMux) {
	h := s.handle
	h(mux, "GET /api/status", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.statusJSON(r.Context()))
	})
	h(mux, "GET /api/status/history", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		sec, _ := strconv.Atoi(r.URL.Query().Get("seconds"))
		if sec < 10 || sec > 1800 {
			sec = 600
		}
		var pts []histPoint
		for _, sn := range s.sampler().History(sec) {
			pts = append(pts, compact(sn))
		}
		writeJSON(w, pts)
	})
	// Server-sent events: a full status snapshot every few seconds.
	h(mux, "GET /api/status/stream", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		every := time.Duration(s.set.get(s.cfg).RefreshSec) * time.Second
		if every < time.Second {
			every = 2 * time.Second
		}
		t := time.NewTicker(every)
		defer t.Stop()
		send := func() {
			b, _ := json.Marshal(s.statusJSON(r.Context()))
			fmt.Fprintf(w, "event: status\ndata: %s\n\n", b)
			fl.Flush()
		}
		send()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-t.C:
				send()
			}
		}
	})
	h(mux, "GET /api/about", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.about())
	})
	h(mux, "GET /metrics", RoleViewer, s.metrics)
}

func (s *Server) about() map[string]any {
	comp := map[string]string{"go": runtime.Version(), "platform": runtime.GOOS + "/" + runtime.GOARCH, "taxonomy": ""}
	if t, err := intel.LoadTaxonomy(); err == nil {
		comp["taxonomy"] = t.Version
	}
	if out, err := exec.Command("docker", "--version").Output(); err == nil {
		comp["docker"] = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("runsc", "--version").Output(); err == nil {
		comp["gvisor"] = strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	}
	return map[string]any{
		"name": brand.Name, "expansion": brand.Expansion, "version": brand.Version, "authors": brand.Authors, "tagline": brand.Tagline,
		"components": comp,
		"started_at": s.started.Format(time.RFC3339),
		"licences": []map[string]string{
			{"name": "pi coding-agent harness (vendored fork)", "licence": "MIT", "url": "https://github.com/earendil-works/pi"},
			{"name": "utopia (bitemporal modelling, design reference)", "licence": "Apache-2.0", "url": "https://github.com/deeplethe/utopia"},
			{"name": "TRIVEKTRA (ported detectors and test vectors)", "licence": "GPL-3.0", "url": ""},
		},
	}
}

// metrics writes Prometheus text exposition. No client library: the format is plain text.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	sn := s.sampler().Latest()
	h := sn.Host
	var b strings.Builder
	g := func(name, help string, v float64, labels ...string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s", name, help, name, name)
		if len(labels) > 0 {
			b.WriteString("{" + strings.Join(labels, ",") + "}")
		}
		fmt.Fprintf(&b, " %g\n", v)
	}
	line := func(name string, v float64, labels ...string) {
		fmt.Fprintf(&b, "%s", name)
		if len(labels) > 0 {
			b.WriteString("{" + strings.Join(labels, ",") + "}")
		}
		fmt.Fprintf(&b, " %g\n", v)
	}
	g("avhsol_host_supported", "1 when host metrics are available on this platform", boolf(h.Supported))
	g("avhsol_host_cpu_percent", "Total CPU use, percent", h.CPU)
	g("avhsol_host_cpu_cores", "Logical CPUs", float64(len(h.Cores)))
	g("avhsol_host_load1", "1-minute load average", h.Load[0])
	g("avhsol_host_load5", "5-minute load average", h.Load[1])
	g("avhsol_host_load15", "15-minute load average", h.Load[2])
	g("avhsol_host_memory_total_bytes", "Physical memory", float64(h.Mem.TotalKB)*1024)
	g("avhsol_host_memory_used_bytes", "Memory in use (total minus available)", float64(h.Mem.UsedKB)*1024)
	g("avhsol_host_memory_cached_bytes", "Page cache", float64(h.Mem.CachedKB)*1024)
	g("avhsol_host_swap_total_bytes", "Swap space", float64(h.Mem.SwapTotalKB)*1024)
	g("avhsol_host_swap_used_bytes", "Swap in use", float64(h.Mem.SwapUsedKB)*1024)
	g("avhsol_host_net_receive_bytes_per_second", "Network receive rate (excluding loopback)", h.NetRx)
	g("avhsol_host_net_transmit_bytes_per_second", "Network transmit rate (excluding loopback)", h.NetTx)
	g("avhsol_host_disk_read_bytes_per_second", "Disk read rate", h.DiskRead)
	g("avhsol_host_disk_write_bytes_per_second", "Disk write rate", h.DiskWrite)
	g("avhsol_host_pressure_cpu_percent", "CPU pressure stall (avg10)", h.PSI.CPU)
	g("avhsol_host_pressure_memory_percent", "Memory pressure stall (avg10)", h.PSI.Mem)
	g("avhsol_host_pressure_io_percent", "IO pressure stall (avg10)", h.PSI.IO)
	g("avhsol_host_uptime_seconds", "Host uptime", h.UptimeSec)
	for _, d := range h.Disks {
		line("avhsol_host_disk_used_bytes", float64(d.Used), `path="`+promEsc(d.Path)+`"`)
		line("avhsol_host_disk_total_bytes", float64(d.Total), `path="`+promEsc(d.Path)+`"`)
	}
	for _, t := range h.Temps {
		line("avhsol_host_temperature_celsius", t.C, `sensor="`+promEsc(t.Label)+`"`)
	}
	for _, p := range sn.Procs {
		line("avhsol_process_rss_bytes", float64(p.RSSBytes), `component="`+promEsc(p.Component)+`"`)
		line("avhsol_process_cpu_percent", p.CPU, `component="`+promEsc(p.Component)+`"`)
	}
	g("avhsol_sandbox_active", "1 while a run is executing", boolf(sn.Sandbox.Active))
	g("avhsol_sandbox_processes", "Processes started by the current run", float64(sn.Sandbox.Procs))
	g("avhsol_sandbox_rss_bytes", "Memory of the current run's processes", float64(sn.Sandbox.RSSBytes))
	g("avhsol_sandbox_cpu_percent", "CPU of the current run's processes (of one core)", sn.Sandbox.CPU)
	for _, c := range sn.Containers {
		line("avhsol_container_cpu_percent", c.CPU, `name="`+promEsc(c.Name)+`",kind="`+c.Kind+`"`)
		line("avhsol_container_memory_bytes", c.MemBytes, `name="`+promEsc(c.Name)+`",kind="`+c.Kind+`"`)
	}
	ri := s.runInfo()
	g("avhsol_runs_active", "Runs currently executing", boolf(ri.Status == "running"))
	ts := s.traceStats()
	line("avhsol_episodes_total", float64(ts.Exploits), `outcome="exploited"`)
	line("avhsol_episodes_total", float64(ts.Valid-ts.Exploits), `outcome="held"`)
	line("avhsol_episodes_total", float64(ts.Errored), `outcome="errored"`)
	line("avhsol_episodes_total", float64(ts.Benign), `outcome="benign"`)
	if m, err := guard.New(s.cfg.GuardURL).Metrics(r.Context()); s.cfg.GuardURL != "" && err == nil {
		var keys []string
		for k := range m.Decisions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			line("avhsol_guard_decisions_total", float64(m.Decisions[k]), `decision="`+k+`"`)
		}
		line("avhsol_guard_decision_latency_microseconds", float64(m.Latency.P50), `quantile="0.5"`)
		line("avhsol_guard_decision_latency_microseconds", float64(m.Latency.P99), `quantile="0.99"`)
	}
	if st, err := intel.Open(intel.Dir()); err == nil {
		g("avhsol_intel_items", "Records in the threat-intel cache", float64(st.Count()))
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

func boolf(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func promEsc(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func baseOrEmpty(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Base(p)
}
