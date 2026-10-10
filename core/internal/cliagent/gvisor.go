package cliagent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/41vi4p/avhsol/core/internal/netmux"
)

// Isolation backends for running the agent under test.
const (
	IsolationLandlock = "landlock" // avhsol-sandbox: Landlock + seccomp on the host kernel (default, no root, no docker)
	IsolationGVisor   = "gvisor"   // Docker with the runsc runtime: the agent talks to gVisor's user-space kernel, not the host's
)

// GVisorConfig tunes the gVisor backend.
type GVisorConfig struct {
	Image string // base image; the host's /usr is mounted over it so host-built agents (node, python) run unchanged
	Mem   string // docker --memory
	Pids  int
	CPUs  string
	// SelfBin is the avhsol binary mounted into the container to tunnel the allowed ports (see `avhsol netfwd`).
	SelfBin string
}

func (c *GVisorConfig) defaults() {
	if c.Image == "" {
		c.Image = "debian:12"
	}
	if c.Mem == "" {
		c.Mem = "2g"
	}
	if c.Pids == 0 {
		c.Pids = 512
	}
	if c.CPUs == "" {
		c.CPUs = "2"
	}
}

// GVisorAvailable reports whether docker with the runsc runtime can be used, and why not if it cannot.
func GVisorAvailable(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{json .Runtimes}}").Output()
	if err != nil {
		return fmt.Errorf("docker is not usable: %w", err)
	}
	if !strings.Contains(string(out), "runsc") {
		return fmt.Errorf("docker has no runsc (gVisor) runtime: install gVisor and register it with `runsc install`")
	}
	return nil
}

func docker(ctx context.Context, args ...string) (string, error) {
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker %s: %v: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// gateway returns the host-side address of the internal bridge, creating the network on first use. The network is
// --internal: containers on it cannot route anywhere, so the only places they can reach are the forwarders AVHSOL
// opens on this address.

// runGVisor runs the agent in a gVisor container with NO network. The workspace is the only writable mount; the host's
// /usr and the target's ro_paths are read-only. The only ports the agent can reach are the allowed ones (the guard
// proxy and the canary sink): inside the container `avhsol netfwd` listens on 127.0.0.1 for them and tunnels each
// connection over the container's stdio to this process, which dials only ports on the allowlist.
func (t *Target) runGVisor(ctx context.Context, cfg GVisorConfig, workspace string, ports []int, v Vars) Result {
	cfg.defaults()
	if err := GVisorAvailable(ctx); err != nil {
		return Result{Err: err.Error()}
	}
	if cfg.SelfBin == "" {
		if exe, err := os.Executable(); err == nil {
			cfg.SelfBin = exe
		}
	}
	if cfg.SelfBin == "" {
		return Result{Err: "gvisor: cannot find the avhsol binary to mount into the container"}
	}
	v = copyVars(v)
	v["workspace"] = workspace
	for name, content := range t.SetupFiles {
		p := filepath.Join(workspace, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return Result{Err: err.Error()}
		}
		if err := os.WriteFile(p, []byte(Expand(content, v)), 0o600); err != nil {
			return Result{Err: err.Error()}
		}
	}
	name := "avhsol-ep-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	args := []string{"run", "--rm", "-i", "--name", name, "--runtime=runsc", "--network", "none",
		"--read-only", "--tmpfs", "/tmp:rw,size=256m", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--pids-limit", strconv.Itoa(cfg.Pids), "--memory", cfg.Mem, "--cpus", cfg.CPUs,
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-v", "/usr:/usr:ro", "-v", workspace + ":" + workspace + ":rw", "-w", workspace,
		"-v", cfg.SelfBin + ":/avhsol-netfwd:ro"}
	for _, p := range t.ReadOnly {
		p = Expand(p, v)
		if p == "" || p == "/proc" || p == "/sys" || strings.HasPrefix(p, "/usr") {
			continue // gVisor provides its own /proc and /sys; /usr is already mounted
		}
		if _, err := os.Stat(p); err == nil {
			args = append(args, "-v", p+":"+p+":ro")
		}
	}
	for k, val := range t.Env {
		args = append(args, "-e", k+"="+Expand(val, v))
	}
	var portStrs []string
	for _, p := range ports {
		portStrs = append(portStrs, strconv.Itoa(p))
	}
	args = append(args, cfg.Image, "/avhsol-netfwd", "netfwd", "-ports", strings.Join(portStrs, ","), "--")
	for _, c := range t.Command {
		args = append(args, Expand(c, v))
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(t.TimeoutSec)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "docker", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return Result{Err: err.Error()}
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{Err: err.Error()}
	}
	var dockerErr bytes.Buffer
	cmd.Stderr = &dockerErr
	cmd.WaitDelay = 3 * time.Second
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return Result{Err: err.Error()}
	}
	var out bytes.Buffer
	code, serveErr := netmux.ServeHost(stdout, stdin, ports, &out)
	_ = stdin.Close()
	waitErr := cmd.Wait()
	if cctx.Err() != nil { // make sure a timed-out container does not keep running
		kctx, kc := context.WithTimeout(context.Background(), 10*time.Second)
		_, _ = docker(kctx, "rm", "-f", name)
		kc()
	}
	res := Result{Stdout: tail(out.String(), 64<<10), Duration: time.Since(start), TimedOut: cctx.Err() == context.DeadlineExceeded}
	switch {
	case res.TimedOut:
	case serveErr != nil && code < 0: // the container ended without reporting an exit status
		msg := strings.TrimSpace(dockerErr.String())
		if msg == "" && waitErr != nil {
			msg = waitErr.Error()
		}
		res.Err = "gvisor container ended abnormally: " + tail(msg, 400)
	default:
		res.ExitCode = code
	}
	return res
}
