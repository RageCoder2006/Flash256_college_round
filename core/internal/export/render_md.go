package export

import (
	"fmt"
	"strings"

	"github.com/41vi4p/avhsol/core/internal/brand"
)

func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r", ""), "\n", " ")
}

func bar(frac float64) string {
	n := int(frac*20 + 0.5)
	if n < 0 {
		n = 0
	}
	if n > 20 {
		n = 20
	}
	return strings.Repeat("█", n) + strings.Repeat("░", 20-n)
}

// RenderMarkdown turns the same resolved document into Markdown (charts become small tables with text bars).
func RenderMarkdown(d *Document) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n_%s: %s_\n\n", d.coverTitle(), brand.Name, brand.Expansion)
	if c := d.Cover; c != nil {
		if c.Classification != "" {
			fmt.Fprintf(&b, "**%s**\n\n", c.Classification)
		}
		if c.Subtitle != "" {
			fmt.Fprintf(&b, "%s\n\n", c.Subtitle)
		}
		for _, m := range c.Meta {
			fmt.Fprintf(&b, "- **%s:** %s\n", m.Label, m.Value)
		}
		b.WriteString("\n")
	}
	if d.TOC {
		b.WriteString("## Contents\n\n")
		for _, s := range d.Sections {
			fmt.Fprintf(&b, "%d. [%s](#%s)\n", s.Number, s.Title, s.ID)
		}
		b.WriteString("\n")
	}
	for _, s := range d.Sections {
		fmt.Fprintf(&b, "<a id=\"%s\"></a>\n\n## %d. %s\n\n", s.ID, s.Number, s.Title)
		for _, blk := range s.Blocks {
			mdBlock(&b, blk)
		}
	}
	fmt.Fprintf(&b, "---\n%s · %s · %s\n", brand.Name, brand.Expansion, brand.Credits())
	return []byte(b.String())
}

func (d *Document) coverTitle() string {
	if d.Cover != nil && d.Cover.Title != "" {
		return d.Cover.Title
	}
	return d.Name
}

func mdBlock(b *strings.Builder, blk RBlock) {
	switch blk.Kind {
	case "heading":
		fmt.Fprintf(b, "%s %s\n\n", strings.Repeat("#", blk.Level+0), blk.Text)
	case "paragraph":
		fmt.Fprintf(b, "%s\n\n", blk.Text)
	case "callout":
		t := blk.Text
		if blk.Title != "" {
			t = "**" + blk.Title + "** " + t
		}
		fmt.Fprintf(b, "> %s\n\n", strings.ReplaceAll(t, "\n", "\n> "))
	case "list":
		for _, l := range blk.Lines {
			fmt.Fprintf(b, "- %s\n", l)
		}
		b.WriteString("\n")
	case "stats", "kv":
		b.WriteString("| | |\n|---|---|\n")
		for _, it := range blk.Items {
			if strings.TrimSpace(it.Value) != "" {
				fmt.Fprintf(b, "| %s | %s |\n", mdEsc(it.Label), mdEsc(it.Value))
			}
		}
		b.WriteString("\n")
	case "table":
		if blk.Title != "" {
			fmt.Fprintf(b, "**%s**\n\n", blk.Title)
		}
		if len(blk.Rows) == 0 {
			if blk.Empty != "" {
				fmt.Fprintf(b, "%s\n\n", blk.Empty)
			}
			return
		}
		fmt.Fprintf(b, "| %s |\n|%s\n", strings.Join(blk.Headers, " | "), strings.Repeat("---|", len(blk.Headers)))
		for _, row := range blk.Rows {
			var cs []string
			for _, c := range row {
				cs = append(cs, mdEsc(c.Text))
			}
			fmt.Fprintf(b, "| %s |\n", strings.Join(cs, " | "))
		}
		b.WriteString("\n")
	case "code":
		txt := blk.Text
		if blk.Reveal {
			var sb strings.Builder
			for _, p := range payloadParts(txt) {
				if p.Hidden {
					sb.WriteString("[hidden: " + p.Text + "]")
				} else {
					sb.WriteString(p.Text)
				}
			}
			txt = sb.String()
		}
		fmt.Fprintf(b, "```\n%s\n```\n\n", strings.ReplaceAll(txt, "```", "'''"))
	case "path":
		var p []string
		for _, n := range blk.Path {
			s := n.Label
			if n.Blocked {
				s += " **[BLOCKED " + n.Rule + "]**"
			}
			p = append(p, s)
		}
		fmt.Fprintf(b, "%s\n\n", strings.Join(p, " → "))
	case "chart":
		if blk.Title != "" {
			fmt.Fprintf(b, "**%s**\n\n", blk.Title)
		}
		switch blk.ChartKind {
		case "bar":
			b.WriteString("| | | |\n|---|---|---|\n")
			for _, r := range blk.Bars {
				den := r.Of
				if den <= 0 {
					den = r.Value
				}
				fmt.Fprintf(b, "| %s | `%s` | %.0f of %.0f |\n", mdEsc(r.Label), bar(pctOf(r.Value, den)), r.Value, r.Of)
			}
		case "compare":
			fmt.Fprintf(b, "| | %s | %s |\n|---|---|---|\n", firstNE(blk.ALabel, "With attack"), firstNE(blk.BLabel, "Control"))
			for _, r := range blk.Compare {
				fmt.Fprintf(b, "| %s | `%s` %.0f of %.0f | `%s` %.0f of %.0f |\n", mdEsc(r.Label), bar(pctOf(r.A, r.AOf)), r.A, r.AOf, bar(pctOf(r.B, r.BOf)), r.B, r.BOf)
			}
		case "donut":
			t := 0.0
			for _, v := range blk.SliceVals {
				t += v
			}
			b.WriteString("| | count | share |\n|---|---|---|\n")
			for i, s := range blk.Slices {
				fmt.Fprintf(b, "| %s | %.0f | %.0f%% |\n", mdEsc(s.Label), blk.SliceVals[i], pctOf(blk.SliceVals[i], t)*100)
			}
		case "strip":
			counts := map[string]int{}
			for _, d := range blk.Dots {
				counts[d.Outcome]++
			}
			b.WriteString("| outcome | runs |\n|---|---|\n")
			for _, k := range []string{"achieved", "held", "errored", "passed", "failed"} {
				if counts[k] > 0 {
					fmt.Fprintf(b, "| %s | %d |\n", k, counts[k])
				}
			}
		}
		b.WriteString("\n")
	case "pagebreak":
		b.WriteString("\n---\n\n")
	}
}
