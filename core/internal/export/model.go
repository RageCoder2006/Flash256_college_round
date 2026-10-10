// Package export turns a directory of runs into a report a security team can hand around: a
// self-contained HTML document, JSON, or SARIF for CI and code-scanning tools.
package export

import (
	"github.com/41vi4p/avhsol/core/internal/advisory"
	"github.com/41vi4p/avhsol/core/internal/audit"
	"github.com/41vi4p/avhsol/core/internal/breach"
	"github.com/41vi4p/avhsol/core/internal/campaign"
	"github.com/41vi4p/avhsol/core/internal/trace"
)

// Finding is one confirmed way to make the agent leak data or break a boundary.
type Finding struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Severity  string   `json:"severity"` // of the objective achieved
	Objective string   `json:"objective"`
	ASI       []string `json:"owasp_agentic"`
	Technique string   `json:"technique"`
	Surface   string   `json:"surface"`
	Operator  string   `json:"operator,omitempty"`
	SeedID    string   `json:"seed_id"`

	Runs            int     `json:"runs"`      // unguarded runs of this exact attack
	Successes       int     `json:"successes"` // of which achieved a critical objective
	Reliability     float64 `json:"reliability"`
	ReliabilityText string  `json:"reliability_text"`

	Evidence    string        `json:"evidence"`
	TraceID     string        `json:"trace_id"`
	Path        []breach.Node `json:"path"`
	Payload     string        `json:"payload"` // redacted
	HiddenChars int           `json:"hidden_chars,omitempty"`

	Timeline []Event `json:"timeline"`

	GuardedRuns      int      `json:"guarded_replays"`
	GuardedSucceeded int      `json:"guarded_replays_still_succeeding"`
	StoppedBy        []string `json:"stopped_by,omitempty"`

	Advisory *advisory.Advisory `json:"advisory,omitempty"`

	// IntelSeed is the advisory the attack seed was derived from, if any. Intel lists related public items.
	IntelSeed string     `json:"intel_seed,omitempty"`
	Intel     []IntelRef `json:"intel,omitempty"`
	Taxonomy  []string   `json:"taxonomy,omitempty"` // OWASP LLM / ASI / ATLAS ids for the technique
	Repro     string     `json:"reproduce"`
}

// Event is one row of an incident timeline: what happened, in order.
type Event struct {
	ts      int64  // for ordering only
	T       string `json:"t"`    // offset from the start of the run, e.g. "+12.4s"
	Type    string `json:"type"` // user_turn | tool_call | tool_result | guard | sandbox
	Summary string `json:"summary"`
	Flag    string `json:"flag,omitempty"` // untrusted | blocked | leak
}

// TechRate is how one attack technique fared across all valid runs.
type TechRate struct {
	Technique string  `json:"technique"`
	Runs      int     `json:"runs"`
	Wins      int     `json:"wins"`
	Rate      float64 `json:"rate"`
}

// RunRow is one line of the event log (appendix) and one dot of the run timeline chart.
type RunRow struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Guard     string `json:"guard"`
	Technique string `json:"technique"`
	Surface   string `json:"surface"`
	Outcome   string `json:"outcome"` // achieved | held | errored | passed | failed
	StartMs   int64  `json:"start_ms"`
	StartedAt string `json:"started_at"`
	DurMs     int64  `json:"duration_ms"`
	Signed    string `json:"signed"`
}

type Recommendation struct {
	Priority  int    `json:"priority"`
	Action    string `json:"action"`
	Rationale string `json:"rationale"`
	Evidence  string `json:"evidence"`
}

// RiskRow is the risk matrix: severity by how reliably the attack worked.
type RiskRow struct {
	Severity string `json:"severity"`
	High     int    `json:"high"`   // worked in 80% or more of runs
	Medium   int    `json:"medium"` // 40-79%
	Low      int    `json:"low"`    // under 40%
	Total    int    `json:"total"`
}

type DocControl struct {
	ReportID       string `json:"report_id"`
	Version        string `json:"version"`
	Classification string `json:"classification"`
	Date           string `json:"date"`
	Status         string `json:"status"`
	Authors        string `json:"authors"`
}

type ScopeObjective struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// Scope states what was tested and how, so the reader can judge what the results cover.
type Scope struct {
	Description string           `json:"description"`
	AgentTools  []string         `json:"agent_tools"`
	Surfaces    []string         `json:"surfaces"`
	Objectives  []ScopeObjective `json:"objectives"`
	Sandboxed   bool             `json:"sandboxed"`
	TargetKind  string           `json:"target_kind"`
	Techniques  []string         `json:"techniques_tried"`
}

type DefenseSummary struct {
	Replayed        int    `json:"replayed"`
	Blocked         int    `json:"blocked"`
	StillSucceeding int    `json:"still_succeeding"`
	BenignOff       string `json:"benign_guard_off"`
	BenignOn        string `json:"benign_guard_on"`
}

// ObjectiveRate is how often an objective was achieved, for attack runs and for the no-attack control.
type ObjectiveRate struct {
	Objective string `json:"objective"`
	Severity  string `json:"severity"`
	Attack    string `json:"attack"`  // "5 of 13"
	Control   string `json:"control"` // "0 of 6" or "not run"
	AttackN   int    `json:"attack_n"`
	AttackK   int    `json:"attack_k"`
	ControlN  int    `json:"control_n"`
	ControlK  int    `json:"control_k"`
}

type Integrity struct {
	Traces       int    `json:"traces"`
	Signed       int    `json:"signed"`
	Verified     int    `json:"verified"`
	Unsigned     int    `json:"unsigned"`
	Failed       int    `json:"failed_verification"`
	KeyID        string `json:"key_id,omitempty"`
	ReportDigest string `json:"report_digest_sha256"`
	ReportSigBy  string `json:"report_signed_by,omitempty"`
	ReportSig    string `json:"report_signature,omitempty"`
}

type Report struct {
	Brand     string `json:"brand"`
	Expansion string `json:"expansion"`
	Authors   string `json:"authors"`
	Generated string `json:"generated_at"`
	Title     string `json:"title"`

	Scenario string `json:"scenario"`
	Target   string `json:"target"`
	Model    string `json:"model"`
	// Simulated is true if any counted run used the simulated model: the report then says so loudly.
	Simulated bool `json:"simulated"`

	AttackRuns  int `json:"attack_runs"`
	ValidRuns   int `json:"valid_runs"`
	ErroredRuns int `json:"errored_runs"`
	ControlRuns int `json:"control_runs"`

	Doc             DocControl       `json:"doc"`
	Scope           Scope            `json:"scope"`
	Headline        string           `json:"headline"`
	Techniques      []TechRate       `json:"techniques"`
	Runs            []RunRow         `json:"runs"`
	Risk            []RiskRow        `json:"risk_matrix"`
	Recommendations []Recommendation `json:"recommendations"`
	DefenseSum      *DefenseSummary  `json:"defense_summary,omitempty"`
	RiskRating      string           `json:"risk_rating"`
	RiskBasis       string           `json:"risk_basis"`
	HasFindings     bool             `json:"has_findings"`
	HasDefense      bool             `json:"has_defense"`
	HasControl      bool             `json:"has_control"`
	HasAdvisories   bool             `json:"has_advisories"`
	HasIntel        bool             `json:"has_intel"`
	BlackBox        bool             `json:"black_box"`
	Isolation       string           `json:"isolation,omitempty"`
	Threat          *ThreatContext   `json:"threat_context,omitempty"`
	Findings        []Finding        `json:"findings"`
	Objectives      []ObjectiveRate  `json:"objectives"`
	NotWorked       []string         `json:"techniques_that_did_not_work"`

	Defense          *campaign.Validation `json:"defense_validation,omitempty"`
	StaticAudit      []trace.Finding      `json:"static_audit"`
	AuditPostureNote string               `json:"-"`

	Limitations []string  `json:"limitations"`
	Integrity   Integrity `json:"integrity"`
}

var _ = audit.Static
