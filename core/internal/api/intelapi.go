package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
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
	// Data sources: what each one is, whether its optional key is set, how many items it holds, and how its last sync went.
	h(mux, "GET /api/intel/sources", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		st, err := intel.Open(intel.Dir())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		srcs := st.Sources()
		for i := range srcs {
			if srcs[i].KeyEnv != "" {
				srcs[i].KeySet = os.Getenv(srcs[i].KeyEnv) != ""
			}
		}
		writeJSON(w, map[string]any{"sources": srcs, "facets": st.Facets(), "dir_private": true})
	})
	// The threat-intelligence knowledge graph, built from the local cache with the same filters as the item list.
	h(mux, "GET /api/intel/graph", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		st, err := intel.Open(intel.Dir())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		q := r.URL.Query()
		n, _ := strconv.Atoi(q.Get("n"))
		writeJSON(w, intel.BuildGraph(st, intel.Filter{Source: q.Get("source"), Kind: q.Get("kind"), Tag: q.Get("tag"), Taxon: q.Get("taxon"), Query: q.Get("q"), KEV: q.Get("kev") == "1"}, n))
	})
	// Query the data sources by meaning (vector search over the intel collection) and by text; semantic hits come first.
	h(mux, "GET /api/intel/search", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		if q == "" || len(q) > 300 {
			http.Error(w, "send ?q= (1 to 300 characters)", http.StatusBadRequest)
			return
		}
		st, err := intel.Open(intel.Dir())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		type hit struct {
			intel.Item
			Score float32 `json:"score,omitempty"`
			Via   string  `json:"via"`
		}
		var out []hit
		seen := map[string]bool{}
		if s.cfg.Graph != nil && s.cfg.Index != nil {
			for _, h := range s.cfg.Graph.SimilarIntel(r.Context(), s.cfg.Index, q, 12) {
				if it, ok := st.Get(h.Source + ":" + h.ID); ok && !seen[it.Key()] {
					seen[it.Key()] = true
					out = append(out, hit{it, h.Score, "meaning"})
				}
			}
		}
		for _, it := range st.Query(intel.Filter{Query: q, Limit: 30}) {
			if !seen[it.Key()] {
				seen[it.Key()] = true
				out = append(out, hit{Item: it, Via: "text"})
			}
		}
		writeJSON(w, map[string]any{"query": q, "semantic": s.cfg.Index != nil, "hits": out})
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
