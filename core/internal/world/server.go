package world

import (
	"encoding/json"
	"net"
	"net/http"
	"sync"
)

// Server routes harness tool calls to the right per-episode World.
type Server struct {
	mu       sync.RWMutex
	episodes map[string]*World
	srv      *http.Server
	ln       net.Listener
}

func NewServer() *Server {
	return &Server{episodes: map[string]*World{}}
}

func (s *Server) Register(id string, w *World) {
	s.mu.Lock()
	s.episodes[id] = w
	s.mu.Unlock()
}

func (s *Server) Unregister(id string) {
	s.mu.Lock()
	delete(s.episodes, id)
	s.mu.Unlock()
}

// Start listens on a loopback ephemeral port and returns its base URL.
func (s *Server) Start() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /episodes/{id}/tool", s.handleTool)
	s.srv = &http.Server{Handler: mux}
	s.ln = ln
	go func() { _ = s.srv.Serve(ln) }()
	return "http://" + ln.Addr().String(), nil
}

func (s *Server) Close() {
	if s.srv != nil {
		_ = s.srv.Close()
	}
}

func (s *Server) handleTool(rw http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	w := s.episodes[r.PathValue("id")]
	s.mu.RUnlock()
	if w == nil {
		http.Error(rw, "unknown episode", http.StatusNotFound)
		return
	}
	var req struct {
		Tool   string         `json:"tool"`
		Args   map[string]any `json:"args"`
		CallID string         `json:"call_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	res := w.Call(req.Tool, req.CallID, req.Args)
	rw.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(rw).Encode(res)
}
