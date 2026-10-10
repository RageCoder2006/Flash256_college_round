package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/41vi4p/avhsol/core/internal/graph"
)

func (s *Server) needGraph(w http.ResponseWriter) bool {
	if s.cfg.Graph == nil {
		http.Error(w, "the trace graph is not configured: start the stack (scripts/stack.sh up) and run serve with -graph", http.StatusServiceUnavailable)
		return false
	}
	return true
}

func clockFrom(r *http.Request) (graph.Clock, error) {
	var c graph.Clock
	for _, p := range []struct {
		q   string
		dst **int64
	}{{"at", &c.At}, {"as_of", &c.AsOf}} {
		v := r.URL.Query().Get(p.q)
		if v == "" {
			continue
		}
		if ms, err := strconv.ParseInt(v, 10, 64); err == nil {
			*p.dst = &ms
			continue
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return c, err
		}
		ms := t.UnixMilli()
		*p.dst = &ms
	}
	return c, nil
}

func filterFrom(r *http.Request) graph.Filter {
	q := r.URL.Query()
	return graph.Filter{Scenario: q.Get("scenario"), Target: q.Get("target"), Model: q.Get("model"), IncludeSimulated: q.Get("simulated") == "1"}
}

func safeID(id string) bool { return id != "" && len(id) < 80 && !strings.ContainsAny(id, "/\\ \n") }

func (s *Server) graphRoutes(mux *http.ServeMux) {
	h := s.handle
	h(mux, "GET /api/graph/status", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"configured": s.cfg.Graph != nil, "vectors": s.cfg.Index != nil, "llm": s.cfg.LLM != nil})
	})
	h(mux, "GET /api/graph/episodes", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		if !s.needGraph(w) {
			return
		}
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n < 1 || n > 500 {
			n = 50
		}
		eps, err := s.cfg.Graph.Episodes(r.Context(), n, filterFrom(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, eps)
	})
	h(mux, "GET /api/graph/episodes/{id}/path", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		if !s.needGraph(w) || !safeID(r.PathValue("id")) {
			return
		}
		p, err := s.cfg.Graph.Why(r.Context(), r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, p)
	})
	h(mux, "GET /api/graph/episodes/{id}/subgraph", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		if !s.needGraph(w) || !safeID(r.PathValue("id")) {
			return
		}
		g, err := s.cfg.Graph.Subgraph(r.Context(), r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, g)
	})
	h(mux, "GET /api/graph/episodes/{id}/beliefs", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		if !s.needGraph(w) || !safeID(r.PathValue("id")) {
			return
		}
		c, err := clockFrom(r)
		if err != nil {
			http.Error(w, "times are RFC3339 or epoch milliseconds", http.StatusBadRequest)
			return
		}
		var bs []graph.Belief
		if r.URL.Query().Get("history") == "1" {
			bs, err = s.cfg.Graph.History(r.Context(), r.PathValue("id"))
		} else {
			bs, err = s.cfg.Graph.Beliefs(r.Context(), r.PathValue("id"), c)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, bs)
	})
	h(mux, "GET /api/graph/techniques", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		if !s.needGraph(w) {
			return
		}
		c, err := clockFrom(r)
		if err != nil {
			http.Error(w, "times are RFC3339 or epoch milliseconds", http.StatusBadRequest)
			return
		}
		ts, err := s.cfg.Graph.Techniques(r.Context(), c, filterFrom(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, ts)
	})
	h(mux, "POST /api/graph/similar", RoleAnalyst, func(w http.ResponseWriter, r *http.Request) {
		if !s.needGraph(w) || s.cfg.Index == nil {
			return
		}
		var b struct {
			Text string `json:"text"`
			K    int    `json:"k"`
			Won  bool   `json:"won"`
			Kind string `json:"kind"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&b) != nil || strings.TrimSpace(b.Text) == "" {
			http.Error(w, "send {text, k?, won?, kind?}", http.StatusBadRequest)
			return
		}
		if b.K < 1 || b.K > 20 {
			b.K = 5
		}
		hits, err := s.cfg.Graph.Similar(r.Context(), s.cfg.Index, b.Text, b.K, b.Kind, b.Won)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, hits)
	})
	h(mux, "POST /api/graph/ask", RoleAnalyst, func(w http.ResponseWriter, r *http.Request) {
		if !s.needGraph(w) {
			return
		}
		if s.cfg.Index == nil || s.cfg.LLM == nil {
			http.Error(w, "asking needs the vector store and a model (set AVHSOL_LLM_BASE_URL / AVHSOL_LLM_MODEL)", http.StatusServiceUnavailable)
			return
		}
		var b struct {
			Question string `json:"question"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&b) != nil || strings.TrimSpace(b.Question) == "" {
			http.Error(w, "send {question}", http.StatusBadRequest)
			return
		}
		a, err := s.cfg.Graph.Ask(r.Context(), s.cfg.Index, s.cfg.LLM, b.Question)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, a)
	})
	h(mux, "POST /api/graph/correct", RoleAnalyst, func(w http.ResponseWriter, r *http.Request) {
		if !s.needGraph(w) {
			return
		}
		var b struct {
			Episode   string `json:"episode"`
			Objective string `json:"objective"`
			Success   bool   `json:"success"`
			Evidence  string `json:"evidence"`
			Reason    string `json:"reason"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&b) != nil || !safeID(b.Episode) || b.Objective == "" || strings.TrimSpace(b.Reason) == "" {
			http.Error(w, "send {episode, objective, success, evidence, reason}; a reason is required", http.StatusBadRequest)
			return
		}
		c := callerOf(r)
		changed, err := s.cfg.Graph.Correct(r.Context(), b.Episode, b.Objective, b.Success, b.Evidence, c.Role.String()+":"+c.ID, b.Reason)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"changed": changed})
	})
}
