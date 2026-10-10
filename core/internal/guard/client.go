// Package guard is the Go client for the Rust abguard-proxy control API.
package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/41vi4p/agentbreak/core/internal/scenario"
)

var AllDefenses = []string{"D1", "D2", "D3", "D4", "D5", "D6", "D7"}

type Capability struct {
	AllowedRecipientDomains []string `json:"allowed_recipient_domains"`
	AllowedHosts            []string `json:"allowed_hosts"`
}

type Policy struct {
	Defenses         []string              `json:"defenses"`
	EgressTools      []string              `json:"egress_tools"`
	DestructiveTools []string              `json:"destructive_tools"`
	UntrustedTools   []string              `json:"untrusted_tools"`
	ProtectedPaths   []string              `json:"protected_paths"`
	Capabilities     map[string]Capability `json:"capabilities"`
}

// PolicyFromScenario derives the guard policy from the scenario's declared capabilities,
// so the manifest the auditor checks is the same one the guard enforces.
func PolicyFromScenario(sc *scenario.Scenario, defenses []string) Policy {
	p := Policy{Defenses: defenses, EgressTools: []string{}, ProtectedPaths: append([]string{}, sc.ProtectedPaths...), DestructiveTools: []string{}, Capabilities: map[string]Capability{}, UntrustedTools: []string{"read_document", "http_fetch", "memory_read"}}
	names := make([]string, 0, len(sc.Capabilities))
	for n := range sc.Capabilities {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c := sc.Capabilities[n]
		if c.Egress {
			p.EgressTools = append(p.EgressTools, n)
		}
		if c.Destructive {
			p.DestructiveTools = append(p.DestructiveTools, n)
		}
		doms := c.AllowedRecipientDomains
		if doms == nil {
			doms = []string{}
		}
		p.Capabilities[n] = Capability{AllowedRecipientDomains: doms, AllowedHosts: []string{}}
	}
	return p
}

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New(baseURL string) *Client {
	return &Client{BaseURL: baseURL, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("guard %s %s: HTTP %d: %s", method, path, res.StatusCode, b)
	}
	if out != nil {
		return json.NewDecoder(res.Body).Decode(out)
	}
	return nil
}

func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, "GET", "/healthz", nil, nil)
}

func (c *Client) SetMode(ctx context.Context, mode string) error {
	return c.do(ctx, "POST", "/v1/guard/mode", map[string]string{"mode": mode}, nil)
}

func (c *Client) PushPolicy(ctx context.Context, p Policy) error {
	return c.do(ctx, "POST", "/v1/guard/policy", p, nil)
}

func (c *Client) Reset(ctx context.Context) error {
	return c.do(ctx, "POST", "/v1/guard/reset", map[string]any{}, nil)
}

type Metrics struct {
	Mode      string         `json:"mode"`
	Decisions map[string]int `json:"decisions"`
	ByRule    map[string]int `json:"by_rule"`
	Latency   struct {
		P50 int `json:"p50"`
		P99 int `json:"p99"`
		N   int `json:"n"`
	} `json:"decision_latency_us"`
	Sanitized map[string]int `json:"sanitized"`
}

func (c *Client) Metrics(ctx context.Context) (*Metrics, error) {
	var m Metrics
	return &m, c.do(ctx, "GET", "/metrics", nil, &m)
}
