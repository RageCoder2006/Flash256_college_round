// Package cliagent runs an existing command-line coding agent (Claude Code, Codex, Gemini CLI,
// opencode, pi, ...) as the target. The agent runs inside avhsol-sandbox, on a decoy workspace, with
// network access limited to the guard proxy (its only route to the model) and the canary sink.
package cliagent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Target struct {
	Name string `yaml:"name"`
	// Command is the argv to run. Placeholders: {task} {workspace} {proxy_url} {api_key} {model}
	// {sink_url} {cwd} {node_dir} {env:NAME}.
	Command []string          `yaml:"command"`
	Env     map[string]string `yaml:"env"`
	// ReadOnly lists extra paths the agent needs to execute (its install dir, node, ...).
	ReadOnly []string `yaml:"ro_paths"`
	// SetupFiles are written into the workspace before the run (agent config pointing at the proxy).
	SetupFiles map[string]string `yaml:"setup_files"`
	TimeoutSec int               `yaml:"timeout_sec"`
	// ToolAliases maps the agent's tool names onto policy names (Bash -> bash).
	ToolAliases map[string]string `yaml:"tool_aliases"`
	// UntrustedTools are the agent's tools whose output is attacker-influenceable (read, WebFetch, ...).
	UntrustedTools []string `yaml:"untrusted_tools"`
}

func Load(path string) (*Target, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Target
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if t.Name == "" || len(t.Command) == 0 {
		return nil, fmt.Errorf("%s: target needs name and command", path)
	}
	if t.TimeoutSec == 0 {
		t.TimeoutSec = 300
	}
	return &t, nil
}

type Vars map[string]string

var placeholderRE = regexp.MustCompile(`\{(env:[A-Za-z0-9_]+|[a-z_]+)\}`)

// Expand substitutes {name} and {env:NAME}; unknown placeholders are left alone.
func Expand(s string, v Vars) string {
	return placeholderRE.ReplaceAllStringFunc(s, func(m string) string {
		k := m[1 : len(m)-1]
		if name, ok := strings.CutPrefix(k, "env:"); ok {
			return os.Getenv(name)
		}
		if val, ok := v[k]; ok {
			return val
		}
		return m
	})
}

// Canonical maps an agent-specific tool name onto the policy's names.
func (t *Target) Canonical(name string) string {
	if a, ok := t.ToolAliases[name]; ok {
		return a
	}
	l := strings.ToLower(name)
	switch l {
	case "bash", "shell", "sh", "terminal", "run_command", "run_shell_command", "execute_bash", "exec_command", "local_shell":
		return "bash"
	}
	if a, ok := t.ToolAliases[l]; ok {
		return a
	}
	return l
}

type Result struct {
	Stdout   string
	ExitCode int
	TimedOut bool
	Duration time.Duration
	Err      string
}

// Run executes the agent for one task inside the sandbox.
func (t *Target) Run(ctx context.Context, sandboxBin, workspace string, ports []int, v Vars) Result {
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
	args := []string{"--workspace", workspace, "--mem", "0", "--nproc", "512", "--cpu", strconv.Itoa(t.TimeoutSec + 60)}
	for _, p := range t.ReadOnly {
		args = append(args, "--ro", Expand(p, v))
	}
	for _, port := range ports {
		args = append(args, "--connect-port", strconv.Itoa(port))
	}
	for k, val := range t.Env {
		args = append(args, "--env", k+"="+Expand(val, v))
	}
	args = append(args, "--")
	for _, c := range t.Command {
		args = append(args, Expand(c, v))
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(t.TimeoutSec)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, sandboxBin, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out // stdin stays closed: agents must never wait on a terminal
	cmd.WaitDelay = 2 * time.Second
	start := time.Now()
	err := cmd.Run()
	res := Result{Stdout: tail(out.String(), 64<<10), Duration: time.Since(start), TimedOut: cctx.Err() == context.DeadlineExceeded}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		} else {
			res.Err = err.Error()
		}
	}
	return res
}

func copyVars(v Vars) Vars {
	o := Vars{}
	for k, val := range v {
		o[k] = val
	}
	return o
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
