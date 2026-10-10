// Package harness is the Go side of the stdio JSON-RPC link to the TS (pi) harness.
package harness

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
)

type ScriptedToolCall struct {
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

type ScriptedTurn struct {
	Text      string             `json:"text,omitempty"`
	ToolCalls []ScriptedToolCall `json:"tool_calls,omitempty"`
}

type LLMSpec struct {
	Kind     string         `json:"kind"` // openai | scripted
	BaseURL  string         `json:"base_url,omitempty"`
	Model    string         `json:"model,omitempty"`
	APIKey   string         `json:"api_key,omitempty"`
	Scripted []ScriptedTurn `json:"scripted,omitempty"`
}

type GuardSpec struct {
	URL  string `json:"url"`
	Mode string `json:"mode"`
}

type EpisodeSpec struct {
	EpisodeID    string     `json:"episode_id"`
	WorldURL     string     `json:"world_url"`
	LLM          LLMSpec    `json:"llm"`
	SystemPrompt string     `json:"system_prompt"`
	Tools        []string   `json:"tools"`
	UserTurns    []string   `json:"user_turns"`
	MaxTurns     int        `json:"max_turns,omitempty"`
	Guard        *GuardSpec `json:"guard,omitempty"`
}

type Step struct {
	Type string         `json:"type"`
	TS   int64          `json:"ts"`
	Data map[string]any `json:"data"`
}

type EpisodeResult struct {
	EpisodeID string `json:"episode_id"`
	Steps     []Step `json:"steps"`
	FinalText string `json:"final_text"`
	Turns     int    `json:"turns"`
	Error     string `json:"error,omitempty"`
}

type rpcMsg struct {
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   string          `json:"error,omitempty"`
	Event   string          `json:"event,omitempty"`
	Episode string          `json:"episode_id,omitempty"`
	Step    *Step           `json:"step,omitempty"`
}

// Client owns one harness subprocess and multiplexes episodes over it.
type Client struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	wmu     sync.Mutex
	nextID  atomic.Int64
	mu      sync.Mutex
	pending map[int64]chan rpcMsg
	sinks   map[string]func(Step)
	done    chan struct{}
}

// Start launches the harness. argv is the full command, e.g. ["node", ".../rpc.ts"].
func Start(argv []string) (*Client, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty harness command")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start harness: %w", err)
	}
	c := &Client{cmd: cmd, stdin: in, pending: map[int64]chan rpcMsg{}, sinks: map[string]func(Step){}, done: make(chan struct{})}
	go c.readLoop(out)
	return c, nil
}

func (c *Client) readLoop(r io.Reader) {
	defer close(c.done)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var m rpcMsg
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			continue
		}
		if m.Event == "step" && m.Step != nil {
			c.mu.Lock()
			f := c.sinks[m.Episode]
			c.mu.Unlock()
			if f != nil {
				f(*m.Step)
			}
			continue
		}
		c.mu.Lock()
		ch := c.pending[m.ID]
		delete(c.pending, m.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- m
		}
	}
	// Harness exited: fail anything still waiting.
	c.mu.Lock()
	for id, ch := range c.pending {
		ch <- rpcMsg{ID: id, Error: "harness exited"}
		delete(c.pending, id)
	}
	c.mu.Unlock()
}

func (c *Client) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := c.nextID.Add(1)
	ch := make(chan rpcMsg, 1)
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()
	b, err := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	c.wmu.Lock()
	_, err = c.stdin.Write(append(b, '\n'))
	c.wmu.Unlock()
	if err != nil {
		return nil, err
	}
	select {
	case m := <-ch:
		if m.Error != "" {
			return nil, errors.New(m.Error)
		}
		return m.Result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) Ping(ctx context.Context) error {
	_, err := c.call(ctx, "ping", nil)
	return err
}

// RunEpisode runs one episode; onStep (optional) receives live step events.
func (c *Client) RunEpisode(ctx context.Context, spec EpisodeSpec, onStep func(Step)) (*EpisodeResult, error) {
	if onStep != nil {
		c.mu.Lock()
		c.sinks[spec.EpisodeID] = onStep
		c.mu.Unlock()
		defer func() {
			c.mu.Lock()
			delete(c.sinks, spec.EpisodeID)
			c.mu.Unlock()
		}()
	}
	raw, err := c.call(ctx, "runEpisode", spec)
	if err != nil {
		return nil, err
	}
	var res EpisodeResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *Client) Close() {
	_ = c.stdin.Close()
	select {
	case <-c.done:
	default:
	}
	_ = c.cmd.Wait()
}

type CraftHistory struct {
	Payload     string   `json:"payload"`
	Progress    int      `json:"progress"`
	Note        string   `json:"note"`
	GuardBlocks []string `json:"guard_blocks"`
}

type CraftRequest struct {
	LLM           LLMSpec        `json:"llm"`
	Objective     string         `json:"objective"`
	SurfaceKind   string         `json:"surface_kind"`
	TargetTools   []string       `json:"target_tools"`
	Technique     string         `json:"technique"`
	Operator      string         `json:"operator"`
	SeedText      string         `json:"seed_text"`
	AttackerEmail string         `json:"attacker_email"`
	History       []CraftHistory `json:"history"`
}

type CraftResult struct {
	Payload   string `json:"payload"`
	Rationale string `json:"rationale"`
	Error     string `json:"error,omitempty"`
}

// CraftPayload asks the TS AttackerAgent (a pi agent) for the next payload.
func (c *Client) CraftPayload(ctx context.Context, req CraftRequest) (*CraftResult, error) {
	raw, err := c.call(ctx, "craftPayload", req)
	if err != nil {
		return nil, err
	}
	var res CraftResult
	return &res, json.Unmarshal(raw, &res)
}
