package export

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// SkeletonFormat is the version tag every skeleton file must carry.
const SkeletonFormat = "avhsol-report-skeleton/1"

//go:embed skeletons/*.json
var builtin embed.FS

// Skeleton describes a report as data: which sections, in what order, with which blocks, bound to
// which fields of the report. Changing the report's layout means editing JSON, not code.
//
// Strings may contain {{path}} or {{path|filter}} expressions resolved against the report data
// (inside "each" blocks, the loop variable named by "as" is also available). Filters: pct, upper,
// lower, title, short:N, date, join:SEP, count, num.
type Skeleton struct {
	Format   string    `json:"format"`
	Name     string    `json:"name"`
	Theme    Theme     `json:"theme"`
	Cover    *Cover    `json:"cover,omitempty"`
	Header   string    `json:"header,omitempty"`
	Footer   string    `json:"footer,omitempty"`
	TOC      bool      `json:"toc,omitempty"`
	Sections []Section `json:"sections"`
}

type Theme struct {
	Accent         string `json:"accent,omitempty"` // CSS colour for rules and the cover bar
	Classification string `json:"classification,omitempty"`
}

type Cover struct {
	Classification string `json:"classification,omitempty"`
	Title          string `json:"title"`
	Subtitle       string `json:"subtitle,omitempty"`
	Meta           []Item `json:"meta,omitempty"`
	Note           string `json:"note,omitempty"`
}

type Section struct {
	ID        string  `json:"id,omitempty"`
	Title     string  `json:"title"`
	If        string  `json:"if,omitempty"`
	Unless    string  `json:"unless,omitempty"`
	PageBreak bool    `json:"page_break,omitempty"`
	Blocks    []Block `json:"blocks"`
}

type Item struct {
	Label string `json:"label,omitempty"`
	Value string `json:"value,omitempty"`
	Tone  string `json:"tone,omitempty"` // breach | held | warn | neutral
}

type Column struct {
	Header string `json:"header"`
	Value  string `json:"value"`
	Align  string `json:"align,omitempty"` // left | right | center
	Style  string `json:"style,omitempty"` // plain | mono | pill | severity | outcome
}

type Slice struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Tone  string `json:"tone,omitempty"`
}

type Chart struct {
	Kind  string `json:"kind"` // bar | compare | donut | strip
	Title string `json:"title,omitempty"`
	Data  string `json:"data,omitempty"`
	Tone  string `json:"tone,omitempty"`
	// bar: label, value out of "of"
	Label string `json:"label,omitempty"`
	Value string `json:"value,omitempty"`
	Of    string `json:"of,omitempty"`
	// compare: two series (attack vs control)
	A      string `json:"a,omitempty"`
	AOf    string `json:"a_of,omitempty"`
	B      string `json:"b,omitempty"`
	BOf    string `json:"b_of,omitempty"`
	ALabel string `json:"a_label,omitempty"`
	BLabel string `json:"b_label,omitempty"`
	// donut
	Slices []Slice `json:"slices,omitempty"`
	// strip: dots on a time axis
	Time    string `json:"time,omitempty"`
	Outcome string `json:"outcome,omitempty"`
}

// Block is one element of a section. Which fields apply depends on Type:
//
//	heading (level,text) paragraph (text) list (lines | data+field) callout (tone,text)
//	stats (items) kv (items) table (data,columns,empty) chart (chart) code (text,reveal)
//	attack_path (data) each (data,as,blocks) pagebreak spacer
type Block struct {
	Type   string `json:"type"`
	If     string `json:"if,omitempty"`
	Unless string `json:"unless,omitempty"`

	Level int    `json:"level,omitempty"`
	Text  string `json:"text,omitempty"`
	Tone  string `json:"tone,omitempty"`
	Title string `json:"title,omitempty"`

	Lines []string `json:"lines,omitempty"`
	Items []Item   `json:"items,omitempty"`

	Data    string   `json:"data,omitempty"`
	Field   string   `json:"field,omitempty"`
	Columns []Column `json:"columns,omitempty"`
	Empty   string   `json:"empty,omitempty"`
	Chart   *Chart   `json:"chart,omitempty"`
	Reveal  bool     `json:"reveal_hidden,omitempty"`

	As     string  `json:"as,omitempty"`
	Blocks []Block `json:"blocks,omitempty"`
}

var blockTypes = map[string]bool{"heading": true, "paragraph": true, "list": true, "callout": true, "stats": true, "kv": true,
	"table": true, "chart": true, "code": true, "attack_path": true, "each": true, "pagebreak": true, "spacer": true}
var chartKinds = map[string]bool{"bar": true, "compare": true, "donut": true, "strip": true}

// ParseSkeleton reads and validates a skeleton. Unknown fields are errors, so a typo cannot quietly
// drop part of a report.
func ParseSkeleton(b []byte) (*Skeleton, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var s Skeleton
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("skeleton: %w", err)
	}
	if s.Format != SkeletonFormat {
		return nil, fmt.Errorf("skeleton: format must be %q (got %q)", SkeletonFormat, s.Format)
	}
	if len(s.Sections) == 0 {
		return nil, fmt.Errorf("skeleton: no sections")
	}
	for i, sec := range s.Sections {
		if strings.TrimSpace(sec.Title) == "" {
			return nil, fmt.Errorf("skeleton: section %d has no title", i+1)
		}
		if err := validateBlocks(sec.Blocks, fmt.Sprintf("section %q", sec.Title)); err != nil {
			return nil, err
		}
	}
	return &s, nil
}

func validateBlocks(bs []Block, where string) error {
	for i, b := range bs {
		at := fmt.Sprintf("%s, block %d (%s)", where, i+1, b.Type)
		if !blockTypes[b.Type] {
			return fmt.Errorf("skeleton: %s: unknown block type; use one of heading paragraph list callout stats kv table chart code attack_path each pagebreak spacer", at)
		}
		switch b.Type {
		case "table":
			if b.Data == "" || len(b.Columns) == 0 {
				return fmt.Errorf("skeleton: %s needs data and columns", at)
			}
		case "chart":
			if b.Chart == nil || !chartKinds[b.Chart.Kind] {
				return fmt.Errorf("skeleton: %s needs chart.kind of bar, compare, donut or strip", at)
			}
		case "each":
			if b.Data == "" || b.As == "" || len(b.Blocks) == 0 {
				return fmt.Errorf("skeleton: %s needs data, as and blocks", at)
			}
			if err := validateBlocks(b.Blocks, at); err != nil {
				return err
			}
		case "attack_path":
			if b.Data == "" {
				return fmt.Errorf("skeleton: %s needs data", at)
			}
		case "heading", "paragraph", "callout", "code":
			if b.Text == "" {
				return fmt.Errorf("skeleton: %s needs text", at)
			}
		}
	}
	return nil
}

// LoadSkeleton loads a skeleton by built-in name ("security-report", "executive-brief") or file path.
func LoadSkeleton(nameOrPath string) (*Skeleton, error) {
	if nameOrPath == "" {
		nameOrPath = "security-report"
	}
	if !strings.ContainsAny(nameOrPath, "/\\.") {
		b, err := builtin.ReadFile("skeletons/" + nameOrPath + ".json")
		if err != nil {
			return nil, fmt.Errorf("no built-in skeleton %q (available: %s)", nameOrPath, strings.Join(BuiltinSkeletons(), ", "))
		}
		return ParseSkeleton(b)
	}
	b, err := os.ReadFile(nameOrPath)
	if err != nil {
		return nil, err
	}
	return ParseSkeleton(b)
}

// BuiltinSkeletons lists the skeletons shipped in the binary.
func BuiltinSkeletons() []string {
	es, _ := builtin.ReadDir("skeletons")
	var out []string
	for _, e := range es {
		out = append(out, strings.TrimSuffix(e.Name(), ".json"))
	}
	return out
}

// BuiltinSkeletonJSON returns a built-in skeleton's source so it can be copied and customised.
func BuiltinSkeletonJSON(name string) ([]byte, error) {
	return builtin.ReadFile("skeletons/" + name + ".json")
}
