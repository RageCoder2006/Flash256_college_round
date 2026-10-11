package api

import (
	"io"
	"net/http"

	"github.com/41vi4p/avhsol/core/internal/mcpserver"
	"github.com/41vi4p/avhsol/core/internal/tools"
)

// mcpAllowed is the administrator's allow-list; with none set, the defaults apply (nothing that launches agents).
func (s *Server) mcpAllowed(t tools.Tool) bool {
	v := s.set.get(s.cfg)
	if len(v.MCPTools) == 0 {
		return tools.DefaultExposed(t)
	}
	for _, n := range v.MCPTools {
		if n == t.Name {
			return true
		}
	}
	return false
}

func (s *Server) toolEnv() tools.Env {
	return tools.Env{OutDirs: []string{s.cfg.OutDir}, Exe: s.cfg.Exe}
}

func (s *Server) toolsRoutes(mux *http.ServeMux) {
	h := s.handle
	// Everything the platform can do, and which of it is served over MCP right now.
	h(mux, "GET /api/tools", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		v := s.set.get(s.cfg)
		type row struct {
			tools.Tool
			Role    string `json:"role"`
			Allowed bool   `json:"mcp_allowed"` // in the allow-list (whether or not the endpoint is switched on)
			Exposed bool   `json:"mcp_exposed"` // allowed AND the endpoint is on
		}
		var rows []row
		for _, t := range tools.All() {
			rows = append(rows, row{Tool: t, Role: Role(t.MinRole).String(), Allowed: s.mcpAllowed(t), Exposed: v.MCPEnabled && s.mcpAllowed(t)})
		}
		writeJSON(w, map[string]any{
			"tools": rows, "mcp_enabled": v.MCPEnabled,
			"connect": map[string]string{
				"stdio": "claude mcp add avhsol -- avhsol mcp",
				"http":  "claude mcp add --transport http avhsol http://" + r.Host + "/mcp --header \"Authorization: Bearer $AVHSOL_TOKEN\"",
			},
		})
	})
	// MCP over Streamable HTTP: one JSON-RPC message per POST. Same tokens and roles as the REST API.
	h(mux, "POST /mcp", RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		if !s.set.get(s.cfg).MCPEnabled {
			http.Error(w, "the MCP endpoint is switched off (Settings > Tools)", http.StatusServiceUnavailable)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		who := callerOf(r)
		srv := &mcpserver.Server{Env: s.toolEnv(), Role: int(who.Role), Allowed: s.mcpAllowed}
		srv.OnCall = func(tool string, ok bool, note string) {
			st := 200
			if !ok {
				st = 400
			}
			s.cfg.Audit.Write(AuditEntry{Remote: clientIP(r), Method: "MCP", Path: "tools/call " + tool, Who: who.ID, Role: who.Role.String(), Status: st, Note: note})
		}
		reply := srv.Handle(r.Context(), body)
		if reply == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(reply)
	})
}
