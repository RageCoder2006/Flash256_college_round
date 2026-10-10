package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/41vi4p/avhsol/core/internal/intel"
)

var syncMu sync.Mutex // one sync at a time

func (s *Server) intelRoutes(mux *http.ServeMux) {
	h := s.handle
	h(mux, "GET /api/intel/status", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		st, err := intel.Open(intel.Dir())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tax, _ := intel.LoadTaxonomy()
		v := ""
		if tax != nil {
			v = tax.Version
		}
		writeJSON(w, map[string]any{"items": st.Count(), "sources": st.State.Sources, "taxonomy": v})
	})
	h(mux, "GET /api/intel/items", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		st, err := intel.Open(intel.Dir())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		q := r.URL.Query()
		n, _ := strconv.Atoi(q.Get("n"))
		if n < 1 || n > 500 {
			n = 50
		}
		writeJSON(w, st.Query(intel.Filter{Source: q.Get("source"), Kind: q.Get("kind"), Tag: q.Get("tag"), Taxon: q.Get("taxon"), Query: q.Get("q"), KEV: q.Get("kev") == "1", Limit: n}))
	})
	// Fetching from the network is an explicit administrator action and is always audited.
	h(mux, "POST /api/intel/sync", RoleAdmin, func(w http.ResponseWriter, r *http.Request) {
		if !syncMu.TryLock() {
			http.Error(w, "a sync is already running", http.StatusConflict)
			return
		}
		defer syncMu.Unlock()
		var b struct {
			Sources []string `json:"sources"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&b)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer cancel()
		sy, err := intel.Defaults(intel.Dir())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rep := sy.Run(ctx, b.Sources)
		if err := sy.Store.Save(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if s.cfg.Graph != nil {
			if _, err := s.cfg.Graph.IngestIntel(ctx, sy.Store.Query(intel.Filter{}), s.cfg.Index); err != nil {
				rep.Results = append(rep.Results, intel.SourceResult{Source: "graph", Error: err.Error()})
			}
		}
		writeJSON(w, rep)
	})
}
