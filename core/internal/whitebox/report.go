package whitebox

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/41vi4p/avhsol/core/internal/scengen"
)

// Counts returns findings per severity.
func (r *Report) Counts() map[string]int {
	m := map[string]int{}
	for _, f := range r.Findings {
		m[f.Severity]++
	}
	for _, d := range r.DepFinds {
		s := d.Severity
		if s == "" {
			s = "medium"
		}
		m[s]++
	}
	return m
}

// Print writes the human-readable static report.
func (r *Report) Print(w io.Writer) {
	fmt.Fprintf(w, "== static code audit: %s\n   %s\n", r.Name, r.Dir)
	fmt.Fprintf(w, "   languages: %s   frameworks: %s   files read: %d\n", orNone(r.Languages), orNone(r.Frameworks), r.Files)
	if len(r.Tools) == 0 {
		fmt.Fprintln(w, "\ntools: none recognised")
	} else {
		fmt.Fprintf(w, "\ntools the agent exposes to its model (%d):\n", len(r.Tools))
		tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  name\twhere\tconfidence\troles\tcode does")
		for _, t := range r.Tools {
			fmt.Fprintf(tw, "  %s\t%s:%d\t%s\t%s\t%s\n", t.Name, t.File, t.Line, t.Confidence, strings.Join(shortRoles(t.Roles), ","), strings.Join(t.Hints, ","))
		}
		tw.Flush()
	}
	fmt.Fprintf(w, "\nfindings (%d):\n", len(r.Findings))
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "  none from the code patterns")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(w, "  %s  [%s confidence]\n", f.String(), f.Confidence)
		if f.Evidence != "" {
			fmt.Fprintf(w, "      > %s\n", f.Evidence)
		}
		if f.Fix != "" {
			fmt.Fprintf(w, "      fix: %s\n", f.Fix)
		}
	}
	fmt.Fprintf(w, "\ndependencies: %d read; check: %s\n", r.Deps, depMode(r.DepsChecked))
	for _, d := range r.DepFinds {
		kev := ""
		if d.KEV {
			kev = " KEV"
		}
		exact := "version matched"
		if !d.Exact {
			exact = "name only: check your version"
		}
		fmt.Fprintf(w, "  [%s] %s %s@%s  %s%s (%s)\n", strings.ToUpper(orStr(d.Severity, "unrated")), d.Dep.Ecosystem, d.Dep.Name, orStr(d.Dep.Version, "?"), strings.Join(firstN(d.IDs, 4), ", "), kev, exact)
	}
	for _, x := range r.Warnings {
		fmt.Fprintf(w, "note: %s\n", x)
	}
	fmt.Fprintln(w, "\nlimits of this audit:")
	for _, l := range r.Limits {
		fmt.Fprintf(w, "  - %s\n", l)
	}
}

func depMode(m string) string {
	switch m {
	case "online":
		return "exact versions against OSV"
	case "offline-name-only":
		return "names only, against the local threat-intel cache (add --online for exact versions)"
	}
	return "not checked (no network and no local threat-intel cache)"
}

func orNone(l []string) string {
	if len(l) == 0 {
		return "none detected"
	}
	return strings.Join(l, ", ")
}

func orStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func firstN(l []string, n int) []string {
	if len(l) > n {
		return l[:n]
	}
	return l
}

func shortRoles(rs []string) []string {
	m := map[string]string{scengen.RoleUntrustedRead: "untrusted-in", scengen.RoleSensitiveRead: "sensitive-read", scengen.RoleEgress: "egress", scengen.RoleDestructive: "destructive", scengen.RoleMemory: "memory", scengen.RoleShell: "shell"}
	var out []string
	for _, r := range rs {
		out = append(out, m[r])
	}
	return out
}

// WriteFiles saves the report as JSON, SARIF and the generated scenario in dir.
func (res *Result) WriteFiles(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(res.Report, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "whitebox.json"), b, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "whitebox.sarif"), res.Report.SARIF(), 0o644); err != nil {
		return err
	}
	if res.Scenario != nil { // in a scenarios/ directory so the report engine can find it by id
		if err := os.MkdirAll(filepath.Join(dir, "scenarios"), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "scenarios", res.Scenario.ID+".yaml"), scengen.YAML(res.Scenario), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// SARIF renders the findings as SARIF 2.1.0 so the audit can gate CI.
func (r *Report) SARIF() []byte {
	level := map[string]string{"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
	type loc = map[string]any
	rules := map[string]loc{}
	var results []loc
	for _, f := range r.Findings {
		rules[f.ID] = loc{"id": f.ID, "name": f.ID, "shortDescription": loc{"text": f.Title}, "fullDescription": loc{"text": f.Detail}, "help": loc{"text": f.Fix}}
		res := loc{"ruleId": f.ID, "level": level[f.Severity], "message": loc{"text": f.Title + ". " + f.Detail}}
		if f.File != "" {
			res["locations"] = []loc{{"physicalLocation": loc{"artifactLocation": loc{"uri": f.File}, "region": loc{"startLine": max1(f.Line)}}}}
		}
		results = append(results, res)
	}
	for _, d := range r.DepFinds {
		id := "WB-DEP-VULN"
		rules[id] = loc{"id": id, "name": id, "shortDescription": loc{"text": "Dependency with known advisories"}}
		results = append(results, loc{"ruleId": id, "level": "warning", "message": loc{"text": fmt.Sprintf("%s %s@%s: %s", d.Dep.Ecosystem, d.Dep.Name, d.Dep.Version, strings.Join(d.IDs, ", "))},
			"locations": []loc{{"physicalLocation": loc{"artifactLocation": loc{"uri": d.Dep.File}, "region": loc{"startLine": 1}}}}})
	}
	var rl []loc
	for _, v := range rules {
		rl = append(rl, v)
	}
	doc := loc{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []loc{{"tool": loc{"driver": loc{"name": "avhsol whitebox", "rules": rl}}, "results": results}}}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return b
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
