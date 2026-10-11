// Package whitebox audits an AI agent's own source code: it detects the framework, finds the tools the agent
// exposes to its model, flags risky code and vulnerable dependencies, and builds the test scenario used for the
// dynamic attack. It reads files; it never executes anything from the audited directory and never writes into it.
package whitebox

// Finding is one thing the static audit found.
type Finding struct {
	ID         string `json:"id"`       // stable rule id, e.g. WB-SHELL-SINK
	Severity   string `json:"severity"` // critical | high | medium | low | info
	Title      string `json:"title"`    // one line
	Detail     string `json:"detail"`   // why it matters
	File       string `json:"file,omitempty"`
	Line       int    `json:"line,omitempty"`
	Evidence   string `json:"evidence,omitempty"` // the matching line, secrets reduced to fingerprints
	Fix        string `json:"fix,omitempty"`
	Confidence string `json:"confidence"`      // high | medium | low: how sure the pattern is
	Count      int    `json:"count,omitempty"` // further places with the same pattern (folded into this finding)
}

// Tool is one capability the agent hands to its model.
type Tool struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Args        []string `json:"args,omitempty"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Confidence  string   `json:"confidence"`
	Source      string   `json:"source"`          // how it was found: declaration | decorator | server.tool | json-schema | mcp-config
	Hints       []string `json:"hints,omitempty"` // what the code around it does: shell, eval, file_write, http, sql, env
	Roles       []string `json:"roles,omitempty"`
	Canonical   string   `json:"canonical,omitempty"`
}

// Dep is one dependency from a manifest or lock file.
type Dep struct {
	Ecosystem string `json:"ecosystem"` // npm | PyPI | Go | crates.io
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"` // exact when known
	File      string `json:"file"`
	Direct    bool   `json:"direct"`
}

// DepFinding is a known-vulnerable dependency.
type DepFinding struct {
	Dep      Dep      `json:"dep"`
	IDs      []string `json:"ids"`
	Summary  string   `json:"summary,omitempty"`
	Severity string   `json:"severity,omitempty"`
	KEV      bool     `json:"kev,omitempty"`
	EPSS     float64  `json:"epss,omitempty"`
	Exact    bool     `json:"exact"` // true when matched on the exact version (OSV); false for a name-only match against the local cache
}

// Report is everything the static audit produced.
type Report struct {
	Dir         string       `json:"dir"`
	Name        string       `json:"name"`
	Languages   []string     `json:"languages"`
	Frameworks  []string     `json:"frameworks"`
	Files       int          `json:"files_scanned"`
	Tools       []Tool       `json:"tools"`
	Findings    []Finding    `json:"findings"`
	Deps        int          `json:"dependencies"`
	DepFinds    []DepFinding `json:"vulnerable_dependencies"`
	DepsChecked string       `json:"dependency_check"` // online | offline-name-only | none
	Warnings    []string     `json:"warnings,omitempty"`
	Limits      []string     `json:"limits"`
}

// Limits are printed with every report: what a pattern-based reader cannot promise.
var Limits = []string{
	"Pattern-based: tools registered dynamically at run time, or built by code the scanner does not recognise, can be missed.",
	"A match is a lead, not proof: harmless code can match and the confidence column says how sure each pattern is. The dynamic attack is what proves exploitability.",
	"Dependencies are checked by exact version only with --online; otherwise only package names are compared with the local threat-intel cache.",
}

var sevOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
