// Package runtime starts the helper processes an audit needs, so `avhsol .` works without a hand-started stack.
package runtime

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/41vi4p/avhsol/core/internal/home"
)

// Proxy is a running (or reused) avhsol-proxy.
type Proxy struct {
	URL     string // base URL without /v1, e.g. http://127.0.0.1:41234
	Started bool   // true when this process started it (and Stop ends it)
	cmd     *exec.Cmd
	done    chan struct{}
}

// Options configure EnsureProxy.
type Options struct {
	Existing string // base URL of a proxy that is already running (-guard-url / AVHSOL_GUARD_URL)
	Upstream string // OpenAI-compatible base URL of the model (…/v1)
	Model    string // replaces the model name the audited agent asks for
	APIKey   string // upstream key; passed to the proxy by environment only
	Bin      string // avhsol-proxy binary (default: home.Bin)
	Mode     string // guard mode at start: off|monitor|enforce (default off)
}

// Healthy reports whether a proxy answers /healthz at base.
func Healthy(ctx context.Context, base string) bool {
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(c, http.MethodGet, strings.TrimRight(base, "/")+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// FreePort returns a loopback address with a free port.
func FreePort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}

// EnsureProxy returns a reachable guard proxy: the existing one when it answers, otherwise a new avhsol-proxy bound to a
// free loopback port whose upstream is the configured model endpoint.
func EnsureProxy(ctx context.Context, o Options) (*Proxy, error) {
	if o.Existing != "" {
		if !Healthy(ctx, o.Existing) {
			return nil, fmt.Errorf("guard proxy at %s does not answer /healthz", o.Existing)
		}
		return &Proxy{URL: strings.TrimRight(o.Existing, "/")}, nil
	}
	bin := o.Bin
	if bin == "" {
		bin = home.Bin("avhsol-proxy")
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Errorf("avhsol-proxy not found (%s): build it with `cargo build --release` in guard/, or run scripts/install.sh", bin)
	}
	addr, err := FreePort()
	if err != nil {
		return nil, err
	}
	mode := o.Mode
	if mode == "" {
		mode = "off"
	}
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		"AVHSOL_GUARD_ADDR="+addr, "AVHSOL_UPSTREAM="+o.Upstream, "AVHSOL_GUARD_MODE="+mode,
		"AVHSOL_UPSTREAM_MODEL="+o.Model, "AVHSOL_UPSTREAM_KEY="+o.APIKey)
	cmd.Stdout, cmd.Stderr = nil, nil // never echo: the proxy's environment holds the upstream key
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &Proxy{URL: "http://" + addr, Started: true, cmd: cmd, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(p.done) }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-p.done:
			return nil, fmt.Errorf("avhsol-proxy exited at start-up (is %s already in use?)", addr)
		case <-ctx.Done():
			p.Stop()
			return nil, ctx.Err()
		default:
		}
		if Healthy(ctx, p.URL) {
			return p, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	p.Stop()
	return nil, fmt.Errorf("avhsol-proxy did not become healthy at %s", addr)
}

// Stop ends a proxy this process started; a reused proxy is left running.
func (p *Proxy) Stop() {
	if p == nil || !p.Started || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
	}
}
