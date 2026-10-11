package whitebox

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/41vi4p/avhsol/core/internal/cliagent"
	"github.com/41vi4p/avhsol/core/internal/home"
	"gopkg.in/yaml.v3"
)

// RepoConfig is the optional avhsol.yaml an agent repository carries. It says how to launch the agent for the dynamic attack.
type RepoConfig struct {
	Name string `yaml:"name"`
	// Target names a ready-made target template in targets/ (for example pi-coding-agent) or a path to one.
	Target string `yaml:"target"`
	// Run is the argv that starts the agent for one task. {task} is replaced by the user turn; {agent_dir} is the
	// audited directory (mounted read-only); the working directory is the decoy workspace.
	Run []string `yaml:"run"`
	// ModelEnv picks which base-URL variables point the agent at the guard proxy: openai (default), anthropic or both.
	ModelEnv string            `yaml:"model_env"`
	Env      map[string]string `yaml:"env"`
	ROPaths  []string          `yaml:"ro_paths"`
	// Setup lists commands the agent needs once (build, install). They are shown, never run for you.
	Setup     []string `yaml:"setup"`
	Build     string   `yaml:"build"`
	ToolsFile string   `yaml:"tools_file"`
	Timeout   int      `yaml:"timeout_sec"`
}

// LoadRepoConfig reads dir/avhsol.yaml. A missing file is not an error.
func LoadRepoConfig(dir string) (*RepoConfig, error) {
	b, err := os.ReadFile(filepath.Join(dir, "avhsol.yaml"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c RepoConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	switch c.ModelEnv {
	case "", "openai", "anthropic", "both":
	default:
		return nil, fmt.Errorf("model_env must be openai, anthropic or both")
	}
	if c.Target == "" && len(c.Run) == 0 {
		return &c, fmt.Errorf("needs target: or run:")
	}
	return &c, nil
}

// Profile says how to launch a recognised agent without any configuration.
type Profile struct {
	Name      string
	Framework string
	Reason    string
	// TargetFile is the target definition used for the run (a template under targets/ or one built from avhsol.yaml).
	TargetFile string
	Target     *cliagent.Target
	// Ready is "" when the agent can start now, else what is missing.
	Missing string
	// BuildCmd builds the agent (shown and run outside the sandbox only with the user's go-ahead).
	BuildCmd []string
	AgentDir string
}

// DetectProfile recognises the agent in dir: avhsol.yaml first, then built-in profiles (pi).
func DetectProfile(dir string, cfg *RepoConfig) *Profile {
	if cfg != nil {
		if p := profileFromConfig(dir, cfg); p != nil {
			return p
		}
	}
	if isPi(dir) {
		return piProfile(dir)
	}
	return nil
}

func isPi(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err == nil {
		var pj struct{ Name string }
		if json.Unmarshal(b, &pj) == nil && pj.Name == "pi-monorepo" {
			return true
		}
	}
	b, err = os.ReadFile(filepath.Join(dir, "packages", "coding-agent", "package.json"))
	return err == nil && strings.Contains(string(b), "pi-coding-agent")
}

func piProfile(dir string) *Profile {
	p := &Profile{Name: "pi-coding-agent", Framework: "pi", AgentDir: dir, Reason: "recognised the pi monorepo (packages/coding-agent)"}
	p.TargetFile = home.Resolve("targets/pi-coding-agent.yaml")
	t, err := cliagent.Load(p.TargetFile)
	if err != nil {
		p.Missing = "target template targets/pi-coding-agent.yaml not found (" + err.Error() + ")"
		return p
	}
	p.Target = t
	if _, err := exec.LookPath("node"); err != nil {
		p.Missing = "node is not on PATH"
	}
	if _, err := os.Stat(filepath.Join(dir, "packages", "coding-agent", "dist", "cli.js")); err != nil {
		// the same steps as `make pi-build`; dependencies are installed without running their install scripts
		if _, nerr := os.Stat(filepath.Join(dir, "node_modules")); nerr != nil {
			p.BuildCmd = []string{"sh", "-c", "npm install --ignore-scripts && npm run hydrate:model-data && npm run build:offline"}
			if p.Missing == "" {
				p.Missing = "pi is not built and its dependencies are not installed (no node_modules)"
			}
		} else {
			p.BuildCmd = []string{"sh", "-c", "npm run hydrate:model-data && npm run build:offline"}
			if p.Missing == "" {
				p.Missing = "pi is not built (packages/coding-agent/dist/cli.js is missing)"
			}
		}
	}
	return p
}

func profileFromConfig(dir string, c *RepoConfig) *Profile {
	p := &Profile{Name: c.Name, Framework: "avhsol.yaml", AgentDir: dir, Reason: "avhsol.yaml"}
	if p.Name == "" {
		p.Name = filepath.Base(dir)
	}
	if c.Build != "" {
		p.BuildCmd = strings.Fields(c.Build)
	}
	if c.Target != "" {
		path := c.Target
		if !strings.ContainsAny(path, "/\\") && !strings.HasSuffix(path, ".yaml") {
			path = "targets/" + path + ".yaml"
		}
		if !filepath.IsAbs(path) {
			if _, err := os.Stat(filepath.Join(dir, path)); err == nil {
				path = filepath.Join(dir, path)
			} else {
				path = home.Resolve(path)
			}
		}
		t, err := cliagent.Load(path)
		if err != nil {
			p.Missing = err.Error()
			return p
		}
		p.Target, p.TargetFile = t, path
		return p
	}
	if len(c.Run) == 0 {
		p.Missing = "avhsol.yaml has no run: command"
		return p
	}
	t := &cliagent.Target{Name: p.Name, Kind: "cli", Wire: "openai", Command: c.Run, Env: map[string]string{}, TimeoutSec: c.Timeout, UntrustedTools: []string{"*"}}
	if t.TimeoutSec == 0 {
		t.TimeoutSec = 300
	}
	t.Isolation = cliagent.IsolationLandlock
	t.Env["TERM"] = "dumb"
	t.Env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
	if exe, err := exec.LookPath(c.Run[0]); err == nil {
		if rp, err := filepath.EvalSymlinks(exe); err == nil {
			bin := filepath.Dir(rp)
			t.ReadOnly = append(t.ReadOnly, filepath.Dir(bin))
			t.Env["PATH"] = bin + ":" + t.Env["PATH"]
		}
	}
	mode := c.ModelEnv
	if mode == "" {
		mode = "openai"
	}
	if mode == "openai" || mode == "both" {
		for _, k := range []string{"OPENAI_BASE_URL", "OPENAI_API_BASE"} {
			t.Env[k] = "{proxy_url}/v1"
		}
		t.Env["OPENAI_API_KEY"] = "{api_key}"
	}
	if mode == "anthropic" || mode == "both" {
		t.Env["ANTHROPIC_BASE_URL"] = "{proxy_url}"
		t.Env["ANTHROPIC_API_KEY"] = "{api_key}"
		t.Wire = "anthropic"
	}
	t.Env["AVHSOL_MODEL"] = "{model}"
	for k, v := range c.Env {
		t.Env[k] = v
	}
	t.ReadOnly = append(t.ReadOnly, "{agent_dir}", "/proc", "/sys")
	t.ReadOnly = append(t.ReadOnly, c.ROPaths...)
	p.Target = t
	p.TargetFile = filepath.Join(dir, "avhsol.yaml")
	return p
}

// WriteTarget writes the launch definition used for a run, so the run directory records exactly what was started.
func (p *Profile) WriteTarget(path string) error {
	if p.Target == nil {
		return fmt.Errorf("no launch definition")
	}
	b, err := yaml.Marshal(p.Target)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
