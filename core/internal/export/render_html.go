package export

import (
	"fmt"
	"html"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/41vi4p/avhsol/core/internal/brand"
)

type part struct {
	Text   string
	Hidden bool
}

// payloadParts makes invisible characters visible: Unicode "tag" characters decode to the ASCII they
// smuggle, other zero-width characters become a bracketed code point.
func payloadParts(s string) []part {
	var out []part
	var buf, hid strings.Builder
	flushBuf := func() {
		if buf.Len() > 0 {
			out = append(out, part{buf.String(), false})
			buf.Reset()
		}
	}
	flushHid := func() {
		if hid.Len() > 0 {
			out = append(out, part{hid.String(), true})
			hid.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r >= 0xE0020 && r <= 0xE007E:
			flushBuf()
			hid.WriteRune(r - 0xE0000)
		case (r >= 0xE0000 && r <= 0xE007F) || (r >= 0x200B && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2060 && r <= 0x2064) || r == 0xFEFF:
			flushBuf()
			fmt.Fprintf(&hid, "⟨U+%04X⟩", r)
		default:
			flushHid()
			buf.WriteRune(r)
		}
	}
	flushBuf()
	flushHid()
	return out
}

func e(s string) string { return html.EscapeString(s) }

var toneColour = map[string]string{"breach": "var(--breach)", "held": "var(--held)", "warn": "var(--warn)", "neutral": "var(--ink3)", "": "var(--breach)"}

func tone(t string) string {
	if c, ok := toneColour[t]; ok {
		return c
	}
	return toneColour[""]
}

const css = `
:root{--bg:#eef1f4;--surface:#fff;--s2:#e8ecf0;--ink:#141f2a;--ink2:#4b5a68;--ink3:#7a8896;--line:#d3dae1;--breach:#c81e4a;--breach-s:#f8dde5;--held:#0b7a75;--held-s:#d5ecea;--warn:#a85f00;--warn-s:#f7e8cc;--accent:#c81e4a}
@media (prefers-color-scheme:dark){:root{--bg:#0f1820;--surface:#16222c;--s2:#1e2d39;--ink:#e8eef3;--ink2:#a5b3bf;--ink3:#74838f;--line:#2a3b48;--breach:#ff5c80;--breach-s:#3a1c27;--held:#3fcfc6;--held-s:#123a38;--warn:#f0b04a;--warn-s:#3a2c12}}
*{box-sizing:border-box}html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{margin:0;background:var(--bg);color:var(--ink);font:14.5px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.page{max-width:980px;margin:0 auto;padding:24px 20px 56px}
.cover{background:var(--surface);border:1px solid var(--line);border-top:10px solid var(--accent);border-radius:6px;padding:46px 44px 36px;min-height:640px;display:flex;flex-direction:column;margin-bottom:26px}
.cover .mark{font-weight:800;letter-spacing:.14em;font-size:15px}.cover .exp{color:var(--ink3);font-size:13px;margin-top:2px}
.cover .class{align-self:flex-start;margin-top:34px;border:2px solid var(--accent);color:var(--accent);font-weight:800;letter-spacing:.12em;font-size:12.5px;padding:3px 12px;border-radius:3px}
.cover h1{font-size:clamp(30px,5vw,46px);line-height:1.1;margin:22px 0 8px;letter-spacing:-.01em}.cover .subtitle{font-size:17px;color:var(--ink2);max-width:60ch}
.cover .meta{margin-top:auto;display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px 28px;border-top:1px solid var(--line);padding-top:18px}
.cover .meta dt{font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--ink3)}.cover .meta dd{margin:0 0 4px;font-weight:600;word-break:break-word}
.cover .note{margin-top:16px;color:var(--ink3);font-size:12.5px}
nav.toc{background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:18px 24px;margin-bottom:26px}nav.toc h2{margin:0 0 8px;font-size:16px}nav.toc ol{margin:0;padding-left:20px;columns:2}nav.toc a{color:var(--ink);text-decoration:none}nav.toc a:hover{text-decoration:underline}
section.sec{background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:22px 26px;margin-bottom:20px}
section.sec>h2{margin:0 0 14px;font-size:21px;padding-bottom:8px;border-bottom:2px solid var(--accent)}
h3{font-size:16.5px;margin:22px 0 8px}h4{font-size:14.5px;margin:16px 0 6px;color:var(--ink2)}
p{margin:8px 0}ul,ol{margin:6px 0;padding-left:22px}li{margin:3px 0}
.callout{border-left:5px solid var(--ink3);background:var(--s2);padding:10px 14px;border-radius:4px;margin:12px 0}.callout b{display:block;margin-bottom:2px}
.callout.warn{border-color:var(--warn);background:var(--warn-s)}.callout.breach{border-color:var(--breach);background:var(--breach-s)}.callout.held{border-color:var(--held);background:var(--held-s)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:14px 0}.stat{border:1px solid var(--line);border-radius:6px;padding:12px 14px;border-top:4px solid var(--c,var(--ink3))}.stat .v{font-size:30px;font-weight:750;line-height:1.1}.stat .l{font-size:12.5px;color:var(--ink3);margin-top:4px}
table{border-collapse:collapse;width:100%;font-size:13.5px;margin:10px 0}th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}thead th{background:var(--s2);font-size:11.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--ink2);border-bottom:2px solid var(--line)}
td.right,th.right{text-align:right;font-variant-numeric:tabular-nums}td.center,th.center{text-align:center}
table.kv th{width:220px;background:transparent;text-transform:none;font-size:13px;letter-spacing:0;color:var(--ink3);font-weight:600}table.kv td{font-weight:500}
.pill{display:inline-block;font-size:11.5px;font-weight:700;padding:2px 9px;border-radius:999px;background:var(--s2);color:var(--ink2);white-space:nowrap}.pill.crit{background:var(--breach-s);color:var(--breach)}.pill.ok{background:var(--held-s);color:var(--held)}.pill.warn{background:var(--warn-s);color:var(--warn)}
.mono,pre,code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.3px}pre{background:var(--s2);border:1px solid var(--line);border-radius:5px;padding:10px 12px;white-space:pre-wrap;word-break:break-word;margin:8px 0}
mark{background:var(--warn-s);color:var(--warn);padding:0 2px;border-radius:3px;outline:1px dashed var(--warn)}
.chain{display:flex;flex-wrap:wrap;align-items:center;gap:8px 0;margin:12px 0}.chip{font-size:12px;padding:5px 9px;border-radius:6px;border:1.6px solid var(--c);background:var(--bg-c);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chip.red{--c:var(--breach);--bg-c:var(--breach-s)}.chip.teal{--c:var(--held);--bg-c:var(--held-s)}.chip.ghost{opacity:.4;border-style:dashed}.seam{width:20px;height:2px;background:var(--breach)}.seam.cut{background:none;color:var(--held);font-weight:800;width:30px;text-align:center;height:auto}
.rule{font-family:ui-monospace,monospace;font-size:11px;color:var(--held);font-weight:700;display:block}
figure.chart{margin:14px 0;border:1px solid var(--line);border-radius:6px;padding:12px 14px;background:var(--surface)}figure.chart figcaption{font-weight:650;font-size:13.5px;margin-bottom:6px}figure.chart svg{width:100%;height:auto;display:block}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:12.5px;color:var(--ink2);margin-top:6px}.legend i{display:inline-block;width:11px;height:11px;border-radius:2px;margin-right:6px;vertical-align:-1px}
.finding{border:1px solid var(--line);border-left:6px solid var(--breach);border-radius:6px;padding:4px 18px 14px;margin:18px 0}
footer.doc{margin-top:26px;padding-top:12px;border-top:1px solid var(--line);color:var(--ink3);font-size:12.5px;display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap}
h2,h3,h4{break-after:avoid;page-break-after:avoid}td.mono{white-space:nowrap}table.kv td.mono{white-space:normal}tr{break-inside:avoid;page-break-inside:avoid}
@page{size:A4;margin:16mm 14mm 18mm}
@media print{body{background:#fff}.page{padding:0;max-width:none}.cover{min-height:250mm;page-break-after:always;border-radius:0}section.sec{page-break-inside:auto;border:0;padding:0 0 6px}.finding,figure.chart,table,.stat,.callout{page-break-inside:avoid}.pb{page-break-before:always}nav.toc{page-break-after:always;border:0}}
`

// RenderHTML turns a resolved document into one self-contained HTML file (no scripts, no external requests).
func RenderHTML(d *Document) []byte {
	var b strings.Builder
	accent := d.Theme.Accent
	if accent == "" {
		accent = "#c81e4a"
	}
	b.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex\">")
	fmt.Fprintf(&b, "<title>%s · %s</title><style>%s:root{--accent:%s}%s</style></head><body><div class=\"page\">", e(d.Name), e(brand.Name), css, e(safeColour(accent)), pageFooterCSS(d.Footer))
	if c := d.Cover; c != nil {
		b.WriteString("<header class=\"cover\">")
		fmt.Fprintf(&b, "<div class=\"mark\">%s</div><div class=\"exp\">%s</div>", e(brand.Name), e(brand.Expansion))
		if c.Classification != "" {
			fmt.Fprintf(&b, "<div class=\"class\">%s</div>", e(c.Classification))
		}
		fmt.Fprintf(&b, "<h1>%s</h1>", e(c.Title))
		if c.Subtitle != "" {
			fmt.Fprintf(&b, "<div class=\"subtitle\">%s</div>", e(c.Subtitle))
		}
		b.WriteString("<dl class=\"meta\">")
		for _, m := range c.Meta {
			fmt.Fprintf(&b, "<div><dt>%s</dt><dd>%s</dd></div>", e(m.Label), e(m.Value))
		}
		b.WriteString("</dl>")
		if c.Note != "" {
			fmt.Fprintf(&b, "<div class=\"note\">%s</div>", e(c.Note))
		}
		b.WriteString("</header>")
	}
	if d.TOC {
		b.WriteString("<nav class=\"toc\" aria-label=\"Contents\"><h2>Contents</h2><ol>")
		for _, s := range d.Sections {
			fmt.Fprintf(&b, "<li><a href=\"#%s\">%s</a></li>", e(s.ID), e(s.Title))
		}
		b.WriteString("</ol></nav>")
	}
	for _, s := range d.Sections {
		cls := "sec"
		if s.Break {
			cls += " pb"
		}
		fmt.Fprintf(&b, "<section class=\"%s\" id=\"%s\"><h2>%d. %s</h2>", cls, e(s.ID), s.Number, e(s.Title))
		inFinding := false
		for _, blk := range s.Blocks {
			// a level-3 heading starting with an id like "F-1" opens a bordered finding card
			if blk.Kind == "heading" && blk.Level == 3 && strings.HasPrefix(blk.Text, "F-") {
				if inFinding {
					b.WriteString("</div>")
				}
				b.WriteString("<div class=\"finding\">")
				inFinding = true
			}
			renderBlock(&b, blk)
		}
		if inFinding {
			b.WriteString("</div>")
		}
		b.WriteString("</section>")
	}
	fmt.Fprintf(&b, "<footer class=\"doc\"><span><b>%s</b> · %s</span><span>%s</span><span>%s</span></footer></div></body></html>", e(brand.Name), e(brand.Expansion), e(d.Footer), e(brand.Credits()))
	return []byte(b.String())
}

// safeColour accepts only a CSS colour made of safe characters, since the theme comes from a file.
func safeColour(c string) string {
	for _, r := range c {
		if !(r == '#' || r == '(' || r == ')' || r == ',' || r == '.' || r == ' ' || r == '%' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return "#c81e4a"
		}
	}
	return c
}

func pillClass(style, text string) string {
	t := strings.ToLower(strings.TrimSpace(text))
	switch style {
	case "severity":
		switch t {
		case "critical", "high":
			return "pill crit"
		case "medium":
			return "pill warn"
		}
		return "pill"
	case "outcome":
		switch t {
		case "achieved", "failed", "failed verification":
			return "pill crit"
		case "held", "passed", "verified":
			return "pill ok"
		case "errored", "unsigned":
			return "pill warn"
		}
		return "pill"
	}
	return "pill"
}

func renderBlock(b *strings.Builder, blk RBlock) {
	switch blk.Kind {
	case "heading":
		fmt.Fprintf(b, "<h%d id=\"%s\">%s</h%d>", blk.Level, e(blk.ID), e(blk.Text), blk.Level)
	case "paragraph":
		fmt.Fprintf(b, "<p>%s</p>", e(blk.Text))
	case "callout":
		fmt.Fprintf(b, "<div class=\"callout %s\">", e(blk.Tone))
		if blk.Title != "" {
			fmt.Fprintf(b, "<b>%s</b>", e(blk.Title))
		}
		fmt.Fprintf(b, "%s</div>", e(blk.Text))
	case "list":
		b.WriteString("<ul>")
		for _, l := range blk.Lines {
			fmt.Fprintf(b, "<li>%s</li>", e(l))
		}
		b.WriteString("</ul>")
	case "stats":
		b.WriteString("<div class=\"stats\">")
		for _, it := range blk.Items {
			fmt.Fprintf(b, "<div class=\"stat\" style=\"--c:%s\"><div class=\"v\">%s</div><div class=\"l\">%s</div></div>", tone(it.Tone), e(it.Value), e(it.Label))
		}
		b.WriteString("</div>")
	case "kv":
		b.WriteString("<table class=\"kv\"><tbody>")
		for _, it := range blk.Items {
			if strings.TrimSpace(it.Value) == "" {
				continue
			}
			fmt.Fprintf(b, "<tr><th>%s</th><td>%s</td></tr>", e(it.Label), e(it.Value))
		}
		b.WriteString("</tbody></table>")
	case "table":
		if blk.Title != "" {
			fmt.Fprintf(b, "<h4>%s</h4>", e(blk.Title))
		}
		if len(blk.Rows) == 0 {
			if blk.Empty != "" {
				fmt.Fprintf(b, "<p>%s</p>", e(blk.Empty))
			}
			return
		}
		b.WriteString("<table><thead><tr>")
		for i, h := range blk.Headers {
			al := ""
			if len(blk.Rows) > 0 && i < len(blk.Rows[0]) {
				al = blk.Rows[0][i].Align
			}
			fmt.Fprintf(b, "<th class=\"%s\">%s</th>", e(al), e(h))
		}
		b.WriteString("</tr></thead><tbody>")
		for _, row := range blk.Rows {
			b.WriteString("<tr>")
			for _, c := range row {
				switch c.Style {
				case "pill", "severity", "outcome":
					fmt.Fprintf(b, "<td class=\"%s\"><span class=\"%s\">%s</span></td>", e(c.Align), pillClass(c.Style, c.Text), e(c.Text))
				case "mono":
					fmt.Fprintf(b, "<td class=\"%s mono\">%s</td>", e(c.Align), e(c.Text))
				default:
					fmt.Fprintf(b, "<td class=\"%s\">%s</td>", e(c.Align), e(c.Text))
				}
			}
			b.WriteString("</tr>")
		}
		b.WriteString("</tbody></table>")
	case "code":
		b.WriteString("<pre>")
		if blk.Reveal {
			for _, p := range payloadParts(blk.Text) {
				if p.Hidden {
					fmt.Fprintf(b, "<mark>%s</mark>", e(p.Text))
				} else {
					b.WriteString(e(p.Text))
				}
			}
		} else {
			b.WriteString(e(blk.Text))
		}
		b.WriteString("</pre>")
	case "path":
		renderPath(b, blk.Path)
	case "chart":
		renderChart(b, blk)
	case "pagebreak":
		b.WriteString("<div class=\"pb\"></div>")
	case "spacer":
		b.WriteString("<div style=\"height:12px\"></div>")
	}
}

func renderPath(b *strings.Builder, nodes []PathNode) {
	cut := -1
	for i, n := range nodes {
		if n.Blocked {
			cut = i
			break
		}
	}
	b.WriteString("<div class=\"chain\" role=\"img\" aria-label=\"attack path\">")
	for i, n := range nodes {
		after := cut >= 0 && i > cut
		cls := "red"
		if cut >= 0 {
			cls = "teal"
		}
		if after {
			cls += " ghost"
		}
		if i > 0 {
			if cut >= 0 && i-1 == cut {
				b.WriteString("<span class=\"seam cut\" aria-hidden=\"true\">×</span>")
			} else {
				b.WriteString("<span class=\"seam\"></span>")
			}
		}
		fmt.Fprintf(b, "<span><span class=\"chip %s\" title=\"%s\">%s</span>", cls, e(n.Label), e(n.Label))
		if n.Blocked && n.Rule != "" {
			fmt.Fprintf(b, "<span class=\"rule\">blocked · %s</span>", e(n.Rule))
		}
		b.WriteString("</span>")
	}
	b.WriteString("</div>")
}

// ---- charts: inline SVG, no scripts ----

func renderChart(b *strings.Builder, blk RBlock) {
	b.WriteString("<figure class=\"chart\">")
	if blk.Title != "" {
		fmt.Fprintf(b, "<figcaption>%s</figcaption>", e(blk.Title))
	}
	switch blk.ChartKind {
	case "bar":
		barChart(b, blk)
	case "compare":
		compareChart(b, blk)
	case "donut":
		donutChart(b, blk)
	case "strip":
		stripChart(b, blk)
	}
	b.WriteString("</figure>")
}

func pctOf(v, of float64) float64 {
	if of <= 0 {
		return 0
	}
	return v / of
}

func barChart(b *strings.Builder, blk RBlock) {
	if len(blk.Bars) == 0 {
		b.WriteString("<p class=\"sub\">No data.</p>")
		return
	}
	maxv := 0.0
	for _, r := range blk.Bars {
		maxv = math.Max(maxv, math.Max(r.Of, r.Value))
	}
	const lx, tx, tw, rh = 8.0, 250.0, 330.0, 28.0
	h := float64(len(blk.Bars))*rh + 8
	fmt.Fprintf(b, "<svg viewBox=\"0 0 720 %.0f\" role=\"img\" aria-label=\"%s\">", h, e(blk.Title))
	for i, r := range blk.Bars {
		y := float64(i)*rh + 4
		den := r.Of
		if den <= 0 {
			den = maxv
		}
		frac := pctOf(r.Value, den)
		fmt.Fprintf(b, "<text x=\"%.0f\" y=\"%.1f\" font-size=\"12.5\" fill=\"var(--ink)\">%s</text>", lx, y+14, e(trunc(r.Label, 34)))
		fmt.Fprintf(b, "<rect x=\"%.0f\" y=\"%.1f\" width=\"%.0f\" height=\"14\" rx=\"3\" fill=\"var(--s2)\"/>", tx, y+3, tw)
		if frac > 0 {
			fmt.Fprintf(b, "<rect x=\"%.0f\" y=\"%.1f\" width=\"%.1f\" height=\"14\" rx=\"3\" fill=\"%s\"/>", tx, y+3, math.Max(3, frac*tw), tone(blk.Tone))
		}
		lab := fmt.Sprintf("%.0f", r.Value)
		if r.Of > 0 {
			lab = fmt.Sprintf("%.0f of %.0f  (%.0f%%)", r.Value, r.Of, frac*100)
		}
		fmt.Fprintf(b, "<text x=\"%.0f\" y=\"%.1f\" font-size=\"12\" fill=\"var(--ink2)\">%s</text>", tx+tw+10, y+14, e(lab))
	}
	b.WriteString("</svg>")
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func compareChart(b *strings.Builder, blk RBlock) {
	if len(blk.Compare) == 0 {
		b.WriteString("<p class=\"sub\">No data.</p>")
		return
	}
	const tx, tw, rh = 250.0, 330.0, 40.0
	h := float64(len(blk.Compare))*rh + 8
	fmt.Fprintf(b, "<svg viewBox=\"0 0 720 %.0f\" role=\"img\" aria-label=\"%s\">", h, e(blk.Title))
	for i, r := range blk.Compare {
		y := float64(i)*rh + 4
		fmt.Fprintf(b, "<text x=\"8\" y=\"%.1f\" font-size=\"12.5\" fill=\"var(--ink)\">%s</text>", y+18, e(trunc(r.Label, 34)))
		for j, s := range []struct {
			v, of float64
			col   string
		}{{r.A, r.AOf, "var(--breach)"}, {r.B, r.BOf, "var(--held)"}} {
			yy := y + float64(j)*16
			fmt.Fprintf(b, "<rect x=\"%.0f\" y=\"%.1f\" width=\"%.0f\" height=\"11\" rx=\"3\" fill=\"var(--s2)\"/>", tx, yy+2, tw)
			if f := pctOf(s.v, s.of); f > 0 {
				fmt.Fprintf(b, "<rect x=\"%.0f\" y=\"%.1f\" width=\"%.1f\" height=\"11\" rx=\"3\" fill=\"%s\"/>", tx, yy+2, math.Max(3, f*tw), s.col)
			}
			lab := "not run"
			if s.of > 0 {
				lab = fmt.Sprintf("%.0f of %.0f", s.v, s.of)
			}
			fmt.Fprintf(b, "<text x=\"%.0f\" y=\"%.1f\" font-size=\"11.5\" fill=\"var(--ink2)\">%s</text>", tx+tw+10, yy+11, e(lab))
		}
	}
	b.WriteString("</svg>")
	fmt.Fprintf(b, "<div class=\"legend\"><span><i style=\"background:var(--breach)\"></i>%s</span><span><i style=\"background:var(--held)\"></i>%s</span></div>", e(firstNE(blk.ALabel, "With attack")), e(firstNE(blk.BLabel, "Control")))
}

func donutChart(b *strings.Builder, blk RBlock) {
	total := 0.0
	for _, v := range blk.SliceVals {
		total += v
	}
	if total <= 0 {
		b.WriteString("<p class=\"sub\">No data.</p>")
		return
	}
	const cx, cy, r, sw = 100.0, 100.0, 66.0, 30.0
	circ := 2 * math.Pi * r
	fmt.Fprintf(b, "<svg style=\"max-width:540px\" viewBox=\"0 0 520 200\" role=\"img\" aria-label=\"%s\"><g transform=\"rotate(-90 %.0f %.0f)\">", e(blk.Title), cx, cy)
	off := 0.0
	for i, v := range blk.SliceVals {
		if v <= 0 {
			continue
		}
		seg := v / total * circ
		fmt.Fprintf(b, "<circle cx=\"%.0f\" cy=\"%.0f\" r=\"%.0f\" fill=\"none\" stroke=\"%s\" stroke-width=\"%.0f\" stroke-dasharray=\"%.2f %.2f\" stroke-dashoffset=\"%.2f\"/>", cx, cy, r, tone(blk.Slices[i].Tone), sw, seg, circ-seg, -off)
		off += seg
	}
	fmt.Fprintf(b, "</g><text x=\"%.0f\" y=\"%.0f\" text-anchor=\"middle\" font-size=\"26\" font-weight=\"700\" fill=\"var(--ink)\">%.0f</text><text x=\"%.0f\" y=\"%.0f\" text-anchor=\"middle\" font-size=\"11\" fill=\"var(--ink3)\">total</text>", cx, cy+4, total, cx, cy+20)
	for i, s := range blk.Slices {
		y := 60 + float64(i)*28
		fmt.Fprintf(b, "<rect x=\"220\" y=\"%.0f\" width=\"13\" height=\"13\" rx=\"2\" fill=\"%s\"/><text x=\"242\" y=\"%.0f\" font-size=\"13\" fill=\"var(--ink)\">%s: %.0f (%.0f%%)</text>", y-11, tone(s.Tone), y, e(s.Label), blk.SliceVals[i], blk.SliceVals[i]/total*100)
	}
	b.WriteString("</svg>")
}

var outcomeColour = map[string]string{"achieved": "var(--breach)", "failed": "var(--breach)", "held": "var(--held)", "passed": "var(--held)", "errored": "var(--warn)"}

func stripChart(b *strings.Builder, blk RBlock) {
	if len(blk.Dots) == 0 {
		b.WriteString("<p class=\"sub\">No data.</p>")
		return
	}
	ds := append([]Dot(nil), blk.Dots...)
	sort.Slice(ds, func(i, j int) bool { return ds[i].T < ds[j].T })
	lo, hi := ds[0].T, ds[len(ds)-1].T
	span := float64(hi - lo)
	if span <= 0 {
		span = 1
	}
	const x0, x1 = 24.0, 696.0
	fmt.Fprintf(b, "<svg viewBox=\"0 0 720 120\" role=\"img\" aria-label=\"%s\"><line x1=\"%.0f\" y1=\"60\" x2=\"%.0f\" y2=\"60\" stroke=\"var(--line)\" stroke-width=\"2\"/>", e(blk.Title), x0, x1)
	for i, d := range ds {
		x := x0 + float64(d.T-lo)/span*(x1-x0)
		y := 60 + float64(i%5-2)*13
		col := outcomeColour[d.Outcome]
		if col == "" {
			col = "var(--ink3)"
		}
		fmt.Fprintf(b, "<circle cx=\"%.1f\" cy=\"%.1f\" r=\"5\" fill=\"%s\"><title>%s: %s</title></circle>", x, y, col, e(d.Label), e(d.Outcome))
	}
	fmt.Fprintf(b, "<text x=\"%.0f\" y=\"112\" font-size=\"10.5\" fill=\"var(--ink3)\">%s</text><text x=\"%.0f\" y=\"112\" text-anchor=\"end\" font-size=\"10.5\" fill=\"var(--ink3)\">%s</text>", x0, e(time.UnixMilli(lo).UTC().Format("2006-01-02 15:04")+" UTC"), x1, e(time.UnixMilli(hi).UTC().Format("2006-01-02 15:04")+" UTC"))
	b.WriteString("</svg><div class=\"legend\">")
	for _, k := range []string{"achieved", "held", "errored", "passed", "failed"} {
		fmt.Fprintf(b, "<span><i style=\"background:%s\"></i>%s</span>", outcomeColour[k], k)
	}
	b.WriteString("</div>")
}

// pageFooterCSS puts a running footer and page numbers on every printed page (PDF).
func pageFooterCSS(footer string) string {
	q := strings.NewReplacer("\\", "", "\"", "", "\n", " ", "<", "", ">", "").Replace(footer)
	return fmt.Sprintf("@page{@bottom-left{content:\"%s\";font:8pt system-ui;color:#7a8896}@bottom-right{content:\"Page \" counter(page) \" of \" counter(pages);font:8pt system-ui;color:#7a8896}}", q)
}
