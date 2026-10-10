// Package httpagent drives an agent that is only reachable over HTTP (a chat endpoint). The agent is a black box:
// AVHSOL cannot see its tool calls, only what it answers and what it does to the outside world (a hit on the
// canary sink, a read of the planted document). The report says so.
package httpagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Spec is the target definition (see targets/http-example.yaml).
type Spec struct {
	URL     string            `yaml:"url" json:"url"`
	Method  string            `yaml:"method" json:"method"`
	Headers map[string]string `yaml:"headers" json:"headers"`
	// Body is a template. {task_json} is the message as a JSON string (with quotes), {task} the raw text.
	Body string `yaml:"body" json:"body"`
	// ResponsePath picks the reply out of a JSON answer ("reply", "choices.0.message.content"). Empty = raw body.
	ResponsePath string `yaml:"response_path" json:"response_path"`
	// Placement is how the payload reaches the agent: "url" serves the poisoned document and tells the agent where
	// it is; "inline" appends the payload to the message (direct injection).
	Placement string `yaml:"placement" json:"placement"`
	// PublicHost is how the agent reaches this machine (default 127.0.0.1).
	PublicHost string `yaml:"public_host" json:"public_host"`
	// TaskTemplate wraps the scenario task: {task}, {surface_url}, {payload}.
	TaskTemplate string `yaml:"task_template" json:"task_template"`
	TimeoutSec   int    `yaml:"timeout_sec" json:"timeout_sec"`
}

// Defaults fills what the target file leaves out.
func (s *Spec) Defaults() {
	if s.Method == "" {
		s.Method = "POST"
	}
	if s.Placement == "" {
		s.Placement = "url"
	}
	if s.PublicHost == "" {
		s.PublicHost = "127.0.0.1"
	}
	if s.TimeoutSec == 0 {
		s.TimeoutSec = 120
	}
	if s.Body == "" {
		s.Body = `{"message": {task_json}}`
	}
	if s.TaskTemplate == "" {
		if s.Placement == "inline" {
			s.TaskTemplate = "{task}\n\n{payload}"
		} else {
			s.TaskTemplate = "{task}\n\nThe relevant document is at {surface_url}"
		}
	}
}

// Validate rejects specs that cannot work.
func (s *Spec) Validate() error {
	u, err := url.Parse(s.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("http.url must be an http(s) URL")
	}
	switch s.Placement {
	case "", "url", "inline":
	default:
		return fmt.Errorf("http.placement must be url or inline, not %q", s.Placement)
	}
	return nil
}

// Result is what a drive of the agent produced.
type Result struct {
	Message string // exactly what was sent as the task
	Reply   string
	Status  int
	Err     string
}

func expand(s string, v map[string]string) string {
	for k, val := range v {
		s = strings.ReplaceAll(s, "{"+k+"}", val)
	}
	return s
}

func expandEnv(s string) string {
	for {
		i := strings.Index(s, "{env:")
		if i < 0 {
			return s
		}
		j := strings.Index(s[i:], "}")
		if j < 0 {
			return s
		}
		s = s[:i] + os.Getenv(s[i+5:i+j]) + s[i+j+1:]
	}
}

// Message renders the text sent to the agent.
func (s *Spec) Message(task, surfaceURL, payload string) string {
	return expand(s.TaskTemplate, map[string]string{"task": task, "surface_url": surfaceURL, "payload": payload})
}

// Drive sends the task and returns the agent's reply.
func (s *Spec) Drive(ctx context.Context, message string) Result {
	res := Result{Message: message}
	tj, _ := json.Marshal(message)
	body := expand(s.Body, map[string]string{"task_json": string(tj), "task": message})
	req, err := http.NewRequestWithContext(ctx, s.Method, s.URL, strings.NewReader(body))
	if err != nil {
		res.Err = err.Error()
		return res
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.Headers {
		req.Header.Set(k, expandEnv(v)) // tokens come from the environment, never from the target file
	}
	cl := &http.Client{Timeout: time.Duration(s.TimeoutSec) * time.Second}
	r, err := cl.Do(req)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	res.Status = r.StatusCode
	if r.StatusCode >= 300 {
		res.Err = fmt.Sprintf("agent endpoint answered HTTP %d: %s", r.StatusCode, firstLine(string(b)))
		return res
	}
	res.Reply = Extract(b, s.ResponsePath)
	return res
}

// Extract reads a dotted path out of JSON ("choices.0.message.content"). An empty path returns the raw text.
func Extract(body []byte, path string) string {
	if path == "" {
		return strings.TrimSpace(string(body))
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return strings.TrimSpace(string(body))
	}
	for _, p := range strings.Split(path, ".") {
		switch t := v.(type) {
		case map[string]any:
			v = t[p]
		case []any:
			var i int
			if _, err := fmt.Sscanf(p, "%d", &i); err != nil || i < 0 || i >= len(t) {
				return ""
			}
			v = t[i]
		default:
			return ""
		}
	}
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

// ContentServer serves the poisoned document to the agent for one episode and records who read it, so the trace
// can show the moment the agent took in the untrusted text.
type ContentServer struct {
	ln   net.Listener
	srv  *http.Server
	mu   sync.Mutex
	hits []Fetch
	host string
}

// Fetch is one read of the poisoned document.
type Fetch struct {
	Path    string
	Content string
	At      time.Time
}

// StartContentServer serves {path: text} on an ephemeral port bound to the interface needed to be reachable.
// It binds loopback unless publicHost says otherwise (a remote agent needs the host's address).
func StartContentServer(docs map[string]string, publicHost string) (*ContentServer, error) {
	bind := "127.0.0.1:0"
	if publicHost != "" && publicHost != "127.0.0.1" && publicHost != "localhost" {
		bind = "0.0.0.0:0"
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, err
	}
	cs := &ContentServer{ln: ln, host: publicHost}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		text, ok := docs[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		cs.mu.Lock()
		cs.hits = append(cs.hits, Fetch{Path: r.URL.Path, Content: text, At: time.Now()})
		cs.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.Copy(w, bytes.NewReader([]byte(text)))
	})
	cs.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = cs.srv.Serve(ln) }()
	return cs, nil
}

// URL returns the address of a document.
func (c *ContentServer) URL(doc string) string {
	h := c.host
	if h == "" {
		h = "127.0.0.1"
	}
	_, port, _ := net.SplitHostPort(c.ln.Addr().String())
	return "http://" + net.JoinHostPort(h, port) + "/" + doc
}

// Fetches returns the reads so far.
func (c *ContentServer) Fetches() []Fetch {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Fetch(nil), c.hits...)
}

func (c *ContentServer) Close() { _ = c.srv.Close() }
