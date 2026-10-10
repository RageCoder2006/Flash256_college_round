package scengen

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"time"
)

// ListMCP starts an MCP server over stdio, asks it for its tools and stops it. Only tools/list is called; no tool
// is ever invoked, so listing cannot change anything on the server.
func ListMCP(ctx context.Context, argv []string) ([]ToolSpec, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("no command given")
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer func() { _ = in.Close(); cancel(); _ = cmd.Wait() }()
	send := func(m map[string]any) { b, _ := json.Marshal(m); _, _ = io.WriteString(in, string(b)+"\n") }
	rd := bufio.NewScanner(out)
	rd.Buffer(make([]byte, 0, 1<<16), 1<<22)
	call := func(id int, method string, params any) (json.RawMessage, error) {
		send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
		for rd.Scan() {
			var r struct {
				ID     *int            `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  *struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(rd.Bytes(), &r) != nil || r.ID == nil || *r.ID != id {
				continue // a notification or log line
			}
			if r.Error != nil {
				return nil, fmt.Errorf("%s: %s", method, r.Error.Message)
			}
			return r.Result, nil
		}
		return nil, fmt.Errorf("%s: server closed the connection", method)
	}
	if _, err := call(1, "initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "avhsol-scengen", "version": "1"}}); err != nil {
		return nil, err
	}
	send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	res, err := call(2, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	return ParseTools(res)
}
