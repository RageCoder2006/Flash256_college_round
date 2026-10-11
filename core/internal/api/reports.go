package api

import (
	"archive/zip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/41vi4p/avhsol/core/internal/home"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/41vi4p/avhsol/core/internal/eval"
	"github.com/41vi4p/avhsol/core/internal/export"
	"github.com/41vi4p/avhsol/core/internal/graph"
	"github.com/41vi4p/avhsol/core/internal/sign"
)

// A "run" for reporting is a directory that holds traces/ : the API's output directory and its siblings named out*.
// Requests name a run by its directory name; the path is always resolved from this list, never taken from the request.
func (s *Server) runDirs() map[string]string {
	out := map[string]string{}
	base, err := filepath.Abs(s.cfg.OutDir)
	if err != nil {
		return out
	}
	cands := []string{base}
	if m, _ := filepath.Glob(filepath.Join(filepath.Dir(base), "out*")); len(m) > 0 {
		cands = append(cands, m...)
	}
	for _, c := range cands {
		if fi, err := os.Stat(filepath.Join(c, "traces")); err == nil && fi.IsDir() {
			out[filepath.Base(c)] = c
		}
	}
	return out
}

func (s *Server) resolveRun(id string) (string, bool) {
	if !safeID(id) {
		return "", false
	}
	d, ok := s.runDirs()[id]
	return d, ok
}

// ReportMeta describes a report file stored under <run>/reports.
type ReportMeta struct {
	ID        string `json:"id"`
	Run       string `json:"run"`
	Format    string `json:"format"`
	Skeleton  string `json:"skeleton"`
	Title     string `json:"title,omitempty"`
	Class     string `json:"classification,omitempty"`
	Bytes     int    `json:"bytes"`
	SHA256    string `json:"sha256"`
	CreatedAt string `json:"created_at"`
	CreatedBy string `json:"created_by"`
	File      string `json:"file"`
}

var formatExt = map[string]string{"html": "html", "pdf": "pdf", "md": "md", "json": "json", "sarif": "sarif"}
var formatType = map[string]string{"html": "text/html; charset=utf-8", "pdf": "application/pdf", "md": "text/markdown; charset=utf-8", "json": "application/json", "sarif": "application/sarif+json"}

func (s *Server) exportOptions(dir, scenarioID, title, class string) export.Options {
	o := export.Options{Dir: dir, ScenarioDir: filepath.Dir(s.cfg.ScenarioPath), Scenario: scenarioID, Title: title, Classification: class}
	if pub, err := sign.LoadPublic(graph.Setting("AVHSOL_SIGNING_KEY", "", home.SigningKey()) + ".pub"); err == nil {
		o.Pub = pub
	}
	return o
}

type runRow struct {
	ID        string  `json:"id"`
	Traces    int     `json:"traces"`
	Scenario  string  `json:"scenario"`
	Target    string  `json:"target"`
	Model     string  `json:"model"`
	ValidRuns int     `json:"valid_runs"`
	Exploits  int     `json:"exploits"`
	ASR       float64 `json:"asr"`
	Rating    string  `json:"rating"`
	Simulated bool    `json:"simulated"`
	Findings  int     `json:"findings"`
	Reports   int     `json:"reports"`
	Modified  string  `json:"modified"`
	Error     string  `json:"error,omitempty"`
}

var (
	rowMu    sync.Mutex
	rowCache = map[string]struct {
		mod time.Time
		row runRow
	}{}
)

func (s *Server) runRowFor(id, dir string) runRow {
	tdir := filepath.Join(dir, "traces")
	fi, _ := os.Stat(tdir)
	var mod time.Time
	if fi != nil {
		mod = fi.ModTime()
	}
	files, _ := filepath.Glob(filepath.Join(tdir, "*.json"))
	for _, f := range files[max(0, len(files)-3):] { // newest few files reflect later appends that do not touch the directory time
		if st, err := os.Stat(f); err == nil && st.ModTime().After(mod) {
			mod = st.ModTime()
		}
	}
	rowMu.Lock()
	c, ok := rowCache[dir]
	rowMu.Unlock()
	if ok && c.mod.Equal(mod) && len(files) == c.row.Traces {
		c.row.Reports = len(s.reportMetas(dir))
		return c.row
	}
	row := runRow{ID: id, Traces: len(files), Modified: mod.UTC().Format(time.RFC3339)}
	r, err := export.Build(s.exportOptions(dir, "", "", ""))
	if err != nil {
		row.Error = err.Error()
	} else {
		row.Scenario, row.Target, row.Model, row.ValidRuns, row.Simulated, row.Findings = r.Scenario, r.Target, r.Model, r.ValidRuns, r.Simulated, len(r.Findings)
		row.Rating = r.RiskRating
		for _, o := range r.Objectives {
			if o.Severity == "critical" && o.AttackK > row.Exploits {
				row.Exploits = o.AttackK
			}
		}
		if r.ValidRuns > 0 {
			row.ASR = float64(row.Exploits) / float64(r.ValidRuns)
		}
	}
	rowMu.Lock()
	rowCache[dir] = struct {
		mod time.Time
		row runRow
	}{mod, row}
	rowMu.Unlock()
	row.Reports = len(s.reportMetas(dir))
	return row
}

func (s *Server) reportMetas(dir string) []ReportMeta {
	files, _ := filepath.Glob(filepath.Join(dir, "reports", "*.json"))
	var out []ReportMeta
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var m ReportMeta
		if json.Unmarshal(b, &m) == nil && m.ID != "" {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

func (s *Server) reportRoutes(mux *http.ServeMux) {
	h := s.handle
	h(mux, "GET /api/reports/runs", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		var rows []runRow
		for id, dir := range s.runDirs() {
			rows = append(rows, s.runRowFor(id, dir))
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Modified > rows[j].Modified })
		writeJSON(w, map[string]any{"runs": rows, "skeletons": export.BuiltinSkeletons(), "formats": export.Formats, "pdf": export.PDFAvailable(), "defaults": s.set.get(s.cfg)})
	})
	// The whole report as data: executive summary, scope, findings, defense results, recommendations, limitations, integrity.
	h(mux, "GET /api/reports/runs/{run}/summary", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		dir, ok := s.resolveRun(r.PathValue("run"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		rep, err := export.Build(s.exportOptions(dir, r.URL.Query().Get("scenario"), "", ""))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, rep)
	})
	// The same evaluation `avhsol summary` prints: rates with 95% intervals, comparison with the control, defenses.
	h(mux, "GET /api/reports/runs/{run}/evaluation", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		dir, ok := s.resolveRun(r.PathValue("run"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		rep, err := export.Build(s.exportOptions(dir, r.URL.Query().Get("scenario"), "", ""))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, eval.Summarize(rep))
	})
	h(mux, "GET /api/reports/files", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		dir, ok := s.resolveRun(r.URL.Query().Get("run"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, s.reportMetas(dir))
	})
	h(mux, "POST /api/reports/generate", RoleOperator, func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Run, Skeleton, Format, Title, Classification, Scenario string
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&b) != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		dir, ok := s.resolveRun(b.Run)
		if !ok {
			http.Error(w, "unknown run", http.StatusNotFound)
			return
		}
		set := s.set.get(s.cfg)
		if b.Skeleton == "" {
			b.Skeleton = set.ReportSkeleton
		}
		if b.Format == "" {
			b.Format = "html"
		}
		if b.Title == "" {
			b.Title = set.ReportTitle
		}
		if b.Classification == "" {
			b.Classification = set.Classification
		}
		if _, ok := formatExt[b.Format]; !ok {
			http.Error(w, "format must be html, pdf, md, json or sarif", http.StatusBadRequest)
			return
		}
		known := false
		for _, n := range export.BuiltinSkeletons() {
			known = known || n == b.Skeleton
		}
		if !known || len(b.Title) > 120 || len(b.Classification) > 40 {
			http.Error(w, "unknown skeleton, or title/classification too long", http.StatusBadRequest)
			return
		}
		body, _, err := export.Generate(s.exportOptions(dir, b.Scenario, b.Title, b.Classification), b.Skeleton, b.Format)
		if err != nil {
			code := http.StatusInternalServerError
			if strings.Contains(err.Error(), "no traces") || strings.Contains(err.Error(), "needs Chrome") {
				code = http.StatusBadRequest
			}
			http.Error(w, err.Error(), code)
			return
		}
		rnd := make([]byte, 3)
		_, _ = rand.Read(rnd)
		id := fmt.Sprintf("rpt-%d-%s", time.Now().Unix(), hex.EncodeToString(rnd))
		file := id + "." + formatExt[b.Format]
		rdir := filepath.Join(dir, "reports")
		if err := os.MkdirAll(rdir, 0o755); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sum := sha256.Sum256(body)
		m := ReportMeta{ID: id, Run: b.Run, Format: b.Format, Skeleton: b.Skeleton, Title: b.Title, Class: b.Classification, Bytes: len(body),
			SHA256: hex.EncodeToString(sum[:]), CreatedAt: time.Now().UTC().Format(time.RFC3339), CreatedBy: callerOf(r).ID, File: file}
		mb, _ := json.MarshalIndent(m, "", "  ")
		if err := os.WriteFile(filepath.Join(rdir, file), body, 0o644); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = os.WriteFile(filepath.Join(rdir, id+".json"), mb, 0o644)
		writeJSON(w, m)
	})
	serve := func(w http.ResponseWriter, r *http.Request, download bool) {
		dir, ok := s.resolveRun(r.PathValue("run"))
		id := r.PathValue("id")
		if !ok || !safeID(id) {
			http.NotFound(w, r)
			return
		}
		for _, m := range s.reportMetas(dir) {
			if m.ID != id {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, "reports", m.File))
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", formatType[m.Format])
			w.Header().Set("X-Content-Type-Options", "nosniff")
			// A stored HTML report is self-contained and needs no script. Even if someone opens the URL directly, it may not run any.
			w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:")
			disp := "inline"
			if download {
				disp = "attachment"
			}
			w.Header().Set("Content-Disposition", disp+`; filename="avhsol-`+m.Run+`-`+m.ID+`.`+formatExt[m.Format]+`"`)
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, r)
	}
	h(mux, "GET /api/reports/files/{run}/{id}", RoleViewer, func(w http.ResponseWriter, r *http.Request) { serve(w, r, r.URL.Query().Get("download") == "1") })
	h(mux, "DELETE /api/reports/files/{run}/{id}", RoleAdmin, func(w http.ResponseWriter, r *http.Request) {
		dir, ok := s.resolveRun(r.PathValue("run"))
		id := r.PathValue("id")
		if !ok || !safeID(id) {
			http.NotFound(w, r)
			return
		}
		for _, m := range s.reportMetas(dir) {
			if m.ID == id {
				_ = os.Remove(filepath.Join(dir, "reports", m.File))
				_ = os.Remove(filepath.Join(dir, "reports", id+".json"))
				writeJSON(w, map[string]any{"deleted": id})
				return
			}
		}
		http.NotFound(w, r)
	})
	h(mux, "GET /api/reports/runs/{run}/zip", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		dir, ok := s.resolveRun(r.PathValue("run"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		metas := s.reportMetas(dir)
		if len(metas) == 0 {
			http.Error(w, "no reports have been generated for this run yet", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Disposition", `attachment; filename="avhsol-`+r.PathValue("run")+`-reports.zip"`)
		zw := zip.NewWriter(w)
		defer zw.Close()
		manifest, _ := json.MarshalIndent(metas, "", "  ")
		if f, err := zw.Create("manifest.json"); err == nil {
			_, _ = f.Write(manifest)
		}
		for _, m := range metas {
			b, err := os.ReadFile(filepath.Join(dir, "reports", m.File))
			if err != nil {
				continue
			}
			if f, err := zw.Create(m.File); err == nil {
				_, _ = f.Write(b)
			}
		}
	})
}
