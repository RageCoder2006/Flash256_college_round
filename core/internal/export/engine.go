package export

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---- the resolved document: what the renderers format ----

type Cell struct {
	Text  string
	Style string
	Align string
}

type PathNode struct {
	Kind, Label, Rule string
	Blocked           bool
}

type BarRow struct {
	Label string
	Value float64
	Of    float64
	Note  string
}

type CompareRow struct {
	Label          string
	A, AOf, B, BOf float64
}

type Dot struct {
	T       int64
	Outcome string
	Label   string
}

// RBlock is a block with every expression resolved. Kind selects which fields are meaningful.
type RBlock struct {
	Kind  string // heading paragraph list callout stats kv table chart code path pagebreak spacer
	Level int
	ID    string
	Text  string
	Tone  string
	Lines []string
	Items []Item

	Headers []string
	Rows    [][]Cell
	Empty   string

	ChartKind string
	Title     string
	Bars      []BarRow
	Compare   []CompareRow
	ALabel    string
	BLabel    string
	Slices    []Slice // values resolved to numbers in Text-free form below
	SliceVals []float64
	Dots      []Dot

	Reveal bool
	Path   []PathNode
}

type RSection struct {
	ID     string
	Title  string
	Number int
	Blocks []RBlock
	Break  bool
}

type Document struct {
	Name     string
	Theme    Theme
	Cover    *RCover
	Header   string
	Footer   string
	TOC      bool
	Sections []RSection
}

type RCover struct {
	Classification, Title, Subtitle, Note string
	Meta                                  []Item
}

// ---- data access ----

type scope struct {
	root any
	vars map[string]any
}

func (s scope) with(name string, v any) scope {
	m := map[string]any{}
	for k, x := range s.vars {
		m[k] = x
	}
	m[name] = v
	return scope{root: s.root, vars: m}
}

// ToData converts the report into generic JSON data, the only thing a skeleton can see.
func ToData(r *Report) (any, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	var d any
	return d, json.Unmarshal(b, &d)
}

func (s scope) resolve(path string) (any, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false
	}
	parts := strings.Split(path, ".")
	var cur any
	if v, ok := s.vars[parts[0]]; ok {
		cur, parts = v, parts[1:]
	} else {
		cur = s.root
	}
	for _, p := range parts {
		switch x := cur.(type) {
		case map[string]any:
			v, ok := x[p]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(p)
			if err != nil || i < 0 || i >= len(x) {
				return nil, false
			}
			cur = x[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

func truthy(v any, ok bool) bool {
	if !ok || v == nil {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

func (s scope) shown(ifExpr, unless string) bool {
	if ifExpr != "" {
		neg := strings.HasPrefix(ifExpr, "!")
		v, ok := s.resolve(strings.TrimPrefix(ifExpr, "!"))
		if truthy(v, ok) == neg {
			return false
		}
	}
	if unless != "" {
		v, ok := s.resolve(unless)
		if truthy(v, ok) {
			return false
		}
	}
	return true
}

func num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	}
	return 0
}

func format(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "yes"
		}
		return "no"
	case float64:
		if x == math.Trunc(x) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', 1, 64)
	case []any:
		var p []string
		for _, e := range x {
			p = append(p, format(e))
		}
		return strings.Join(p, ", ")
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

var tpl = regexp.MustCompile(`\{\{\s*([^}|]+?)\s*(?:\|\s*([a-z]+)\s*(?::([^}]*))?)?\s*\}\}`)

// text resolves every {{expr|filter}} in a string. A missing value renders as nothing, never as
// the raw expression, so a typo cannot leak template syntax into a report.
func (s scope) text(in string) string {
	if !strings.Contains(in, "{{") {
		return in
	}
	return tpl.ReplaceAllStringFunc(in, func(m string) string {
		g := tpl.FindStringSubmatch(m)
		v, _ := s.resolve(g[1])
		return applyFilter(v, g[2], strings.TrimSpace(g[3]))
	})
}

func applyFilter(v any, f, arg string) string {
	switch f {
	case "":
		return format(v)
	case "pct":
		return fmt.Sprintf("%.0f%%", num(v)*100)
	case "upper":
		return strings.ToUpper(format(v))
	case "lower":
		return strings.ToLower(format(v))
	case "title":
		t := strings.ReplaceAll(format(v), "_", " ")
		if t == "" {
			return t
		}
		return strings.ToUpper(t[:1]) + t[1:]
	case "short":
		n, _ := strconv.Atoi(arg)
		r := []rune(format(v))
		if n > 0 && len(r) > n {
			return string(r[:n]) + "…"
		}
		return string(r)
	case "count":
		if a, ok := v.([]any); ok {
			return strconv.Itoa(len(a))
		}
		return "0"
	case "num":
		return format(num(v))
	case "join":
		if arg == "" {
			arg = ", "
		}
		if a, ok := v.([]any); ok {
			var p []string
			for _, e := range a {
				p = append(p, format(e))
			}
			return strings.Join(p, arg)
		}
		return format(v)
	case "date":
		str := format(v)
		for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05Z", "2006-01-02"} {
			if t, err := time.Parse(layout, str); err == nil {
				return t.UTC().Format("2 Jan 2006, 15:04 UTC")
			}
		}
		return str
	}
	return format(v)
}

// ---- compile ----

// Compile binds a skeleton to report data and returns the resolved document.
func Compile(sk *Skeleton, data any) (*Document, error) {
	sc := scope{root: data, vars: map[string]any{}}
	d := &Document{Name: sc.text(sk.Name), Theme: sk.Theme, Header: sc.text(sk.Header), Footer: sc.text(sk.Footer), TOC: sk.TOC}
	if sk.Cover != nil {
		c := &RCover{Classification: sc.text(firstNE(sk.Cover.Classification, sk.Theme.Classification)), Title: sc.text(sk.Cover.Title), Subtitle: sc.text(sk.Cover.Subtitle), Note: sc.text(sk.Cover.Note)}
		for _, m := range sk.Cover.Meta {
			if v := sc.text(m.Value); v != "" {
				c.Meta = append(c.Meta, Item{Label: sc.text(m.Label), Value: v, Tone: m.Tone})
			}
		}
		d.Cover = c
	}
	n := 0
	for _, sec := range sk.Sections {
		if !sc.shown(sec.If, sec.Unless) {
			continue
		}
		n++
		rs := RSection{ID: firstNE(sec.ID, "s"+strconv.Itoa(n)), Title: sc.text(sec.Title), Number: n, Break: sec.PageBreak}
		bs, err := compileBlocks(sec.Blocks, sc)
		if err != nil {
			return nil, fmt.Errorf("section %q: %w", sec.Title, err)
		}
		rs.Blocks = bs
		d.Sections = append(d.Sections, rs)
	}
	return d, nil
}

func firstNE(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func compileBlocks(bs []Block, sc scope) ([]RBlock, error) {
	var out []RBlock
	for _, b := range bs {
		if !sc.shown(b.If, b.Unless) {
			continue
		}
		switch b.Type {
		case "heading":
			lvl := b.Level
			if lvl < 2 || lvl > 4 {
				lvl = 3
			}
			out = append(out, RBlock{Kind: "heading", Level: lvl, Text: sc.text(b.Text), ID: slug(sc.text(b.Text))})
		case "paragraph":
			if t := sc.text(b.Text); strings.TrimSpace(t) != "" {
				out = append(out, RBlock{Kind: "paragraph", Text: t})
			}
		case "callout":
			if t := sc.text(b.Text); strings.TrimSpace(t) != "" {
				out = append(out, RBlock{Kind: "callout", Tone: b.Tone, Text: t, Title: sc.text(b.Title)})
			}
		case "list":
			rb := RBlock{Kind: "list"}
			for _, l := range b.Lines {
				if t := sc.text(l); strings.TrimSpace(t) != "" {
					rb.Lines = append(rb.Lines, t)
				}
			}
			if b.Data != "" {
				v, _ := sc.resolve(b.Data)
				if arr, ok := v.([]any); ok {
					for _, e := range arr {
						if b.Field != "" {
							es := sc.with("item", e)
							rb.Lines = append(rb.Lines, es.text("{{item."+b.Field+"}}"))
						} else {
							rb.Lines = append(rb.Lines, format(e))
						}
					}
				}
			}
			if len(rb.Lines) == 0 && b.Empty != "" {
				rb.Lines = []string{sc.text(b.Empty)}
			}
			if len(rb.Lines) > 0 {
				out = append(out, rb)
			}
		case "stats", "kv":
			rb := RBlock{Kind: b.Type}
			for _, it := range b.Items {
				rb.Items = append(rb.Items, Item{Label: sc.text(it.Label), Value: sc.text(it.Value), Tone: it.Tone})
			}
			out = append(out, rb)
		case "table":
			v, _ := sc.resolve(b.Data)
			arr, _ := v.([]any)
			rb := RBlock{Kind: "table", Title: sc.text(b.Title), Empty: sc.text(b.Empty)}
			for _, c := range b.Columns {
				rb.Headers = append(rb.Headers, sc.text(c.Header))
			}
			for _, row := range arr {
				rs := sc.with("row", row)
				var cells []Cell
				for _, c := range b.Columns {
					cells = append(cells, Cell{Text: rs.text(c.Value), Style: c.Style, Align: c.Align})
				}
				rb.Rows = append(rb.Rows, cells)
			}
			out = append(out, rb)
		case "chart":
			rb, err := compileChart(b.Chart, sc)
			if err != nil {
				return nil, err
			}
			out = append(out, rb)
		case "code":
			out = append(out, RBlock{Kind: "code", Text: sc.text(b.Text), Reveal: b.Reveal})
		case "attack_path":
			v, _ := sc.resolve(b.Data)
			rb := RBlock{Kind: "path"}
			if arr, ok := v.([]any); ok {
				for _, e := range arr {
					m, _ := e.(map[string]any)
					bl, _ := m["blocked"].(bool)
					rb.Path = append(rb.Path, PathNode{Kind: format(m["kind"]), Label: format(m["label"]), Rule: format(m["rule"]), Blocked: bl})
				}
			}
			out = append(out, rb)
		case "each":
			v, _ := sc.resolve(b.Data)
			arr, _ := v.([]any)
			if len(arr) == 0 && b.Empty != "" {
				out = append(out, RBlock{Kind: "paragraph", Text: sc.text(b.Empty)})
			}
			for i, item := range arr {
				is := sc.with(b.As, item).with("index", float64(i+1))
				inner, err := compileBlocks(b.Blocks, is)
				if err != nil {
					return nil, err
				}
				out = append(out, inner...)
			}
		case "pagebreak":
			out = append(out, RBlock{Kind: "pagebreak"})
		case "spacer":
			out = append(out, RBlock{Kind: "spacer"})
		}
	}
	return out, nil
}

func compileChart(c *Chart, sc scope) (RBlock, error) {
	rb := RBlock{Kind: "chart", ChartKind: c.Kind, Title: sc.text(c.Title), Tone: c.Tone, ALabel: sc.text(c.ALabel), BLabel: sc.text(c.BLabel)}
	v, _ := sc.resolve(c.Data)
	arr, _ := v.([]any)
	field := func(m map[string]any, expr string) float64 {
		if expr == "" {
			return 0
		}
		if f, ok := m[expr]; ok {
			return num(f)
		}
		return num(sc.with("row", m).text("{{row." + expr + "}}"))
	}
	switch c.Kind {
	case "bar":
		for _, e := range arr {
			m, _ := e.(map[string]any)
			if m == nil {
				continue
			}
			row := BarRow{Label: sc.with("row", m).text("{{row." + c.Label + "}}"), Value: field(m, c.Value), Of: field(m, c.Of)}
			rb.Bars = append(rb.Bars, row)
		}
	case "compare":
		for _, e := range arr {
			m, _ := e.(map[string]any)
			if m == nil {
				continue
			}
			rb.Compare = append(rb.Compare, CompareRow{Label: sc.with("row", m).text("{{row." + c.Label + "}}"), A: field(m, c.A), AOf: field(m, c.AOf), B: field(m, c.B), BOf: field(m, c.BOf)})
		}
	case "donut":
		for _, s := range c.Slices {
			x, ok := sc.resolve(s.Value)
			val := 0.0
			if ok {
				val = num(x)
			} else {
				val = num(sc.text(s.Value))
			}
			rb.Slices = append(rb.Slices, Slice{Label: sc.text(s.Label), Tone: s.Tone})
			rb.SliceVals = append(rb.SliceVals, val)
		}
	case "strip":
		for _, e := range arr {
			m, _ := e.(map[string]any)
			if m == nil {
				continue
			}
			rb.Dots = append(rb.Dots, Dot{T: int64(num(m[c.Time])), Outcome: format(m[c.Outcome]), Label: format(m["id"])})
		}
	default:
		return rb, fmt.Errorf("unknown chart kind %q", c.Kind)
	}
	return rb, nil
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
