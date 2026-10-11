package whitebox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/41vi4p/avhsol/core/internal/home"
	"github.com/41vi4p/avhsol/core/internal/intel"
	"github.com/41vi4p/avhsol/core/internal/scenario"
	"github.com/41vi4p/avhsol/core/internal/scengen"
)

// Options control a scan.
type Options struct {
	Dir    string
	Online bool         // ask OSV for exact-version advisories (sends package names and versions to osv.dev)
	OSV    *OSV         // test hook
	Intel  *intel.Store // optional local threat-intel cache (nil = open the default cache read-only if it exists)
}

// Result is a scan plus what the dynamic attack needs.
type Result struct {
	Report   Report
	Scenario *scenario.Scenario
	Specs    []scengen.ToolSpec
	Classes  []scengen.Class
	Profile  *Profile // how to launch the agent, if known
	Config   *RepoConfig
}

// Scan reads the directory and audits it. It never executes anything from it and never writes to it.
func Scan(ctx context.Context, o Options) (*Result, error) {
	abs, err := filepath.Abs(o.Dir)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", o.Dir)
	}
	code, other, warns, err := walk(abs)
	if err != nil {
		return nil, err
	}
	rep := Report{Dir: abs, Name: filepath.Base(abs), Files: len(code) + len(other), Limits: Limits, Warnings: warns}
	rep.Languages, rep.Frameworks = detect(code, other)
	cfg, cerr := LoadRepoConfig(abs)
	if cerr != nil {
		rep.Warnings = append(rep.Warnings, "avhsol.yaml: "+cerr.Error())
	}
	if cfg != nil && cfg.Name != "" {
		rep.Name = cfg.Name
	}
	rep.Tools = extractTools(code, other)
	if cfg != nil && cfg.ToolsFile != "" {
		if extra, err := toolsFromFile(abs, cfg.ToolsFile); err != nil {
			rep.Warnings = append(rep.Warnings, "tools_file: "+err.Error())
		} else {
			rep.Tools = mergeTools(rep.Tools, extra)
		}
	}
	rep.Findings = runChecks(code, other, rep.Tools)
	if len(rep.Tools) == 0 {
		rep.Warnings = append(rep.Warnings, "no tools were recognised; the generated scenario falls back to a shell-capable coding agent. Add tools_file: to avhsol.yaml if the agent registers tools in a way the scanner cannot see")
	}

	var store *intel.Store
	if o.Intel != nil {
		store = o.Intel
	} else if d := intel.Dir(); dirExists(d) {
		store, _ = intel.Open(d)
	}
	deps := parseDeps(other)
	rep.Deps = len(deps)
	switch {
	case o.Online:
		osv := o.OSV
		if osv == nil {
			osv = &OSV{}
		}
		finds, qerr := osv.Query(ctx, deps)
		if qerr != nil {
			rep.Warnings = append(rep.Warnings, "dependency check (OSV) failed: "+qerr.Error()+"; falling back to names only")
			rep.DepFinds, rep.DepsChecked = nameOnly(deps, store), "offline-name-only"
		} else {
			rep.DepFinds, rep.DepsChecked = enrich(finds, store), "online"
		}
	default:
		rep.DepFinds, rep.DepsChecked = nameOnly(deps, store), "offline-name-only"
		if store == nil {
			rep.DepsChecked = "none"
		}
	}
	sort.Slice(rep.DepFinds, func(i, j int) bool {
		a, b := rep.DepFinds[i], rep.DepFinds[j]
		if a.KEV != b.KEV {
			return a.KEV
		}
		return a.Dep.Name < b.Dep.Name
	})

	res := &Result{Report: rep, Config: cfg}
	for _, t := range rep.Tools {
		if strings.HasPrefix(t.Name, "mcp:") {
			continue
		}
		spec := scengen.ToolSpec{Name: t.Name, Description: t.Description}
		if len(t.Args) > 0 {
			props := map[string]any{}
			for _, a := range t.Args {
				props[a] = map[string]any{}
			}
			spec.Schema = map[string]any{"properties": props}
		}
		res.Specs = append(res.Specs, spec)
	}
	if len(res.Specs) == 0 {
		res.Specs = []scengen.ToolSpec{{Name: "bash", Description: "run a shell command"}, {Name: "read", Description: "read a file"}, {Name: "write", Description: "write a file"}}
	}
	res.Profile = DetectProfile(abs, cfg)
	if res.Profile != nil {
		res.Report.Frameworks = appendUnique(res.Report.Frameworks, res.Profile.Framework)
	}
	for _, s := range res.Specs {
		res.Classes = append(res.Classes, scengen.ClassifyRules(s))
	}
	sc, bw := scengen.Build(res.Specs, res.Classes, scengen.Options{ID: "wb-" + home.Slug(rep.Name), Name: "Whitebox: " + rep.Name})
	res.Scenario = sc
	res.Report.Warnings = append(res.Report.Warnings, bw...)
	// the scenario's own static audit joins the findings
	return res, nil
}

func appendUnique(l []string, v string) []string {
	if v == "" {
		return l
	}
	for _, x := range l {
		if x == v {
			return l
		}
	}
	return append(l, v)
}

func dirExists(d string) bool {
	st, err := os.Stat(d)
	return err == nil && st.IsDir()
}

func mergeTools(a, b []Tool) []Tool {
	have := map[string]bool{}
	for _, t := range a {
		have[strings.ToLower(t.Name)] = true
	}
	for _, t := range b {
		if !have[strings.ToLower(t.Name)] {
			a = append(a, t)
		}
	}
	return a
}

func toolsFromFile(root, rel string) ([]Tool, error) {
	p := rel
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, rel)
	}
	if r, err := filepath.Rel(root, p); err != nil || strings.HasPrefix(r, "..") {
		return nil, fmt.Errorf("must be inside the agent directory")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	specs, err := scengen.ParseTools(b)
	if err != nil {
		return nil, err
	}
	var out []Tool
	for _, s := range specs {
		t := Tool{Name: s.Name, Description: s.Description, File: rel, Line: 1, Confidence: "high", Source: "tools_file"}
		c := scengen.ClassifyRules(s)
		t.Roles, t.Canonical = c.Roles, c.Canon
		out = append(out, t)
	}
	return out, nil
}
