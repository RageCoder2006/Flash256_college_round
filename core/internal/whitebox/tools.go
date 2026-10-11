package whitebox

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/41vi4p/avhsol/core/internal/scengen"
)

var (
	nameLine    = regexp.MustCompile(`\bname\s*[:=]\s*["'` + "`" + `]([A-Za-z][\w.\-]{0,63})["'` + "`" + `]`)
	jsonName    = regexp.MustCompile(`["']name["']\s*:\s*["']([A-Za-z][\w.\-]{0,63})["']`)
	descLine    = regexp.MustCompile(`\bdescription\s*[:=]\s*(?:f?["'` + "`" + `])(.{3,700}?)(?:["'` + "`" + `],?\s*$|["'` + "`" + `]\s*[,)]|$)`)
	execMarker  = regexp.MustCompile(`\b(execute|handler|func|invoke|_run|run|call|callback|parameters|inputSchema|input_schema|args_schema|schema)\b\s*[:=(]`)
	pyDecorator = regexp.MustCompile(`^\s*@(?:\w+\.)?(tool|function_tool|mcp\.tool|server\.tool|agent\.tool|kernel_function|llm\.tool)\b(?:\((.*)\))?\s*$`)
	pyDef       = regexp.MustCompile(`^\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)`)
	serverTool  = regexp.MustCompile(`\b(?:server|mcp|app)\.(?:tool|registerTool)\(\s*["'` + "`" + `]([\w.\-]+)["'` + "`" + `]\s*,?\s*(?:\{[^}]*description\s*:\s*["'` + "`" + `]([^"'` + "`" + `]{0,200}))?`)
	vercelTool  = regexp.MustCompile(`^\s*(?:export\s+)?(?:const|let)\s+(\w+)\s*=\s*(?:tool|createTool|DynamicTool|DynamicStructuredTool|new\s+DynamicTool|new\s+DynamicStructuredTool|StructuredTool|Tool)\s*[(<]`)
	factoryTool = regexp.MustCompile(`^\s*export\s+(?:async\s+)?function\s+create(\w+?)Tool(?:Definition)?\s*[(<]`)
	goTool      = regexp.MustCompile(`\bName:\s*"([\w.\-]+)"`)
)

// capability hints found in the code around a tool.
var hintPats = []struct {
	Hint string
	Pat  *regexp.Regexp
}{
	{"shell", regexp.MustCompile(`(subprocess\.|os\.system|os\.popen|shell\s*=\s*True|child_process|\bexecSync\b|\bspawn(Sync)?\(|\bexec\(|exec\.Command|Runtime\.getRuntime\(\)\.exec|\bcreateShellTool|/bin/(ba)?sh)`)},
	{"eval", regexp.MustCompile(`(\beval\(|new Function\(|\bexec\(compile|ast\.literal_eval|vm\.runIn)`)},
	{"file_write", regexp.MustCompile(`(writeFile|appendFile|fs\.write|open\([^)]*["']w|\.write_text|\.write_bytes|os\.remove|unlink|rmSync|shutil\.rmtree|os\.rename|ioutil\.WriteFile|os\.WriteFile|os\.Remove)`)},
	{"file_read", regexp.MustCompile(`(readFile|readFileSync|\.read_text|open\([^)]*["']r|os\.ReadFile|ioutil\.ReadFile|createReadStream)`)},
	{"http", regexp.MustCompile(`(requests\.(get|post|put|request)|httpx\.|urllib|aiohttp|\bfetch\(|axios|got\(|http\.(Get|Post|NewRequest)|XMLHttpRequest|smtplib|sendmail|webhook)`)},
	{"sql", regexp.MustCompile(`(?i)(\.execute\(|\.query\(|cursor\.|SELECT\s.+\sFROM|INSERT\sINTO|DELETE\sFROM|sqlite3|psycopg|sqlx)`)},
	{"env", regexp.MustCompile(`(os\.environ|os\.getenv|process\.env|os\.Getenv|dotenv)`)},
	{"approval", regexp.MustCompile(`(?i)(confirm|approve|approval|human[_ -]in[_ -]the[_ -]loop|ask_user|requireApproval|needs_approval|permission)`)},
}

func hintsFor(lines []string) []string {
	text := strings.Join(lines, "\n")
	var out []string
	for _, h := range hintPats {
		if h.Pat.MatchString(text) {
			out = append(out, h.Hint)
		}
	}
	return out
}

func window(f *file, from, n int) []string {
	to := from + n
	if to > len(f.Lines) {
		to = len(f.Lines)
	}
	if from < 0 {
		from = 0
	}
	return f.Lines[from:to]
}

// extractTools finds the tools an agent gives its model. Each hit carries where it was found and how sure the pattern is.
func extractTools(code []*file, other map[string]string) []Tool {
	byName := map[string]Tool{}
	add := func(t Tool) {
		if t.Name == "" {
			return
		}
		key := strings.ToLower(t.Name)
		if old, ok := byName[key]; ok && (confRank(old.Confidence) >= confRank(t.Confidence)) {
			return
		}
		byName[key] = t
	}
	for _, f := range code {
		if f.Test {
			continue
		}
		for i, ln := range f.Lines {
			// 1. Python decorators: @tool / @function_tool / @mcp.tool()
			if f.Lang == "Python" {
				if m := pyDecorator.FindStringSubmatch(ln); m != nil {
					for j := i + 1; j < len(f.Lines) && j <= i+4; j++ {
						if d := pyDef.FindStringSubmatch(f.Lines[j]); d != nil {
							desc := pyDocstring(f, j)
							t := Tool{Name: d[1], Description: desc, Args: pyArgs(d[2]), File: f.Rel, Line: j + 1, Confidence: "high", Source: "decorator"}
							t.Hints = hintsFor(window(f, j, 40))
							add(t)
							break
						}
					}
				}
			}
			// 2. server.tool("name", ...) and registerTool
			if m := serverTool.FindStringSubmatch(ln); m != nil {
				t := Tool{Name: m[1], Description: m[2], File: f.Rel, Line: i + 1, Confidence: "high", Source: "server.tool"}
				t.Hints = hintsFor(window(f, i, 40))
				add(t)
			}
			// 3. const x = tool({...}) / DynamicTool / StructuredTool
			if m := vercelTool.FindStringSubmatch(ln); m != nil {
				name, desc := m[1], ""
				for j := i; j < len(f.Lines) && j <= i+12; j++ {
					if nm := nameLine.FindStringSubmatch(f.Lines[j]); nm != nil {
						name = nm[1]
					}
					if dm := descLine.FindStringSubmatch(f.Lines[j]); dm != nil {
						desc = dm[1]
					}
				}
				t := Tool{Name: name, Description: desc, File: f.Rel, Line: i + 1, Confidence: "high", Source: "declaration"}
				t.Hints = hintsFor(window(f, i, 40))
				add(t)
			}
			// 4. generic object literal: name: "x" ... description: "..." ... execute/handler/parameters nearby
			if m := nameLine.FindStringSubmatch(ln); m != nil && !strings.Contains(ln, "package") {
				win := window(f, i, 14)
				joined := strings.Join(win, "\n")
				if descLine.MatchString(joined) && execMarker.MatchString(joined) {
					desc := ""
					if dm := descLine.FindStringSubmatch(joined); dm != nil {
						desc = dm[1]
					}
					t := Tool{Name: m[1], Description: desc, File: f.Rel, Line: i + 1, Confidence: "medium", Source: "declaration"}
					t.Args = schemaArgs(joined)
					t.Hints = hintsFor(window(f, i, 60))
					add(t)
				}
			}
			// 5. OpenAI-style function schema: {"type": "function", "function": {"name": ...}}
			if strings.Contains(ln, `"function"`) || strings.Contains(ln, `'function'`) {
				win := strings.Join(window(f, i, 8), "\n")
				if strings.Contains(win, `"type": "function"`) || strings.Contains(win, `"type":"function"`) || strings.Contains(win, `type: "function"`) || strings.Contains(win, `'type': 'function'`) {
					if nm := jsonName.FindStringSubmatch(win); nm != nil {
						desc := ""
						if dm := regexp.MustCompile(`["']description["']\s*:\s*["']([^"']{3,200})`).FindStringSubmatch(win); dm != nil {
							desc = dm[1]
						}
						// a schema only declares the tool; the code that runs it is elsewhere, so no capability hints are claimed
						add(Tool{Name: nm[1], Description: desc, File: f.Rel, Line: i + 1, Confidence: "high", Source: "json-schema"})
					}
				}
			}
			// 6a. factory convention: export function createBashToolDefinition(...) registers the tool "bash"
			if m := factoryTool.FindStringSubmatch(ln); m != nil && m[1] != "" {
				name := strings.ToLower(m[1][:1]) + m[1][1:]
				t := Tool{Name: name, File: f.Rel, Line: i + 1, Confidence: "medium", Source: "factory", Hints: hintsFor(window(f, i, 60))}
				add(t)
			}
			// 6. Go: a Tool struct literal with a Name field and a Handler/Execute field
			if f.Lang == "Go" {
				if m := goTool.FindStringSubmatch(ln); m != nil {
					win := strings.Join(window(f, i, 10), "\n")
					if regexp.MustCompile(`(?i)(Handler|Execute|Run|Fn|Func)\s*:`).MatchString(win) && strings.Contains(strings.ToLower(win), "description") {
						add(Tool{Name: m[1], File: f.Rel, Line: i + 1, Confidence: "medium", Source: "declaration", Hints: hintsFor(window(f, i, 40))})
					}
				}
			}
		}
	}
	// MCP config files list servers the agent connects to; each server is recorded as a (low-detail) tool surface.
	for rel, txt := range other {
		if isMCPConfig(rel) {
			for _, s := range mcpServers(txt) {
				add(Tool{Name: "mcp:" + s.Name, Description: "MCP server: " + s.Cmd, File: rel, Line: 1, Confidence: "medium", Source: "mcp-config", Hints: nil})
			}
		}
	}
	// classify with the same rules the scenario generator uses
	out := make([]Tool, 0, len(byName))
	for _, t := range byName {
		spec := scengen.ToolSpec{Name: strings.TrimPrefix(t.Name, "mcp:"), Description: t.Description}
		if len(t.Args) > 0 {
			props := map[string]any{}
			for _, a := range t.Args {
				props[a] = map[string]any{}
			}
			spec.Schema = map[string]any{"properties": props}
		}
		c := scengen.ClassifyRules(spec)
		t.Roles, t.Canonical = c.Roles, c.Canon
		// what the code does is stronger evidence than the name
		for _, h := range t.Hints {
			switch h {
			case "shell":
				t.Roles = addRole(t.Roles, scengen.RoleShell, scengen.RoleEgress, scengen.RoleDestructive, scengen.RoleSensitiveRead)
			case "http":
				t.Roles = addRole(t.Roles, scengen.RoleEgress)
			case "file_write":
				t.Roles = addRole(t.Roles, scengen.RoleDestructive)
			case "file_read", "sql":
				t.Roles = addRole(t.Roles, scengen.RoleSensitiveRead)
			}
		}
		sort.Strings(t.Roles)
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}

func addRole(roles []string, add ...string) []string {
	have := map[string]bool{}
	for _, r := range roles {
		have[r] = true
	}
	for _, a := range add {
		if !have[a] {
			roles = append(roles, a)
			have[a] = true
		}
	}
	return roles
}

func confRank(c string) int {
	switch c {
	case "high":
		return 3
	case "medium":
		return 2
	}
	return 1
}

func pyArgs(sig string) []string {
	var out []string
	for _, p := range strings.Split(sig, ",") {
		p = strings.TrimSpace(p)
		p = strings.SplitN(strings.SplitN(p, ":", 2)[0], "=", 2)[0]
		p = strings.TrimSpace(p)
		if p != "" && p != "self" && p != "cls" && !strings.HasPrefix(p, "*") {
			out = append(out, p)
		}
	}
	return out
}

func pyDocstring(f *file, def int) string {
	for j := def + 1; j < len(f.Lines) && j <= def+3; j++ {
		t := strings.TrimSpace(f.Lines[j])
		for _, q := range []string{`"""`, `'''`} {
			if strings.HasPrefix(t, q) {
				t = strings.TrimPrefix(t, q)
				t = strings.TrimSuffix(t, q)
				return clip(strings.TrimSpace(t), 200)
			}
		}
	}
	return ""
}

var propKey = regexp.MustCompile(`["']?(\w{1,30})["']?\s*:\s*(?:\{|z\.|Type\.|S\.|v\.|"|')`)

func schemaArgs(win string) []string {
	var out []string
	seen := map[string]bool{}
	if i := strings.Index(win, "properties"); i >= 0 {
		for _, m := range propKey.FindAllStringSubmatch(win[i:], 12) {
			k := m[1]
			if !seen[k] && k != "type" && k != "description" && k != "properties" && k != "required" && k != "items" && k != "enum" {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return out
}

type mcpServer struct {
	Name, Cmd string
	Args      []string
	Raw       map[string]any
}

func mcpServers(txt string) []mcpServer {
	var doc map[string]any
	if json.Unmarshal([]byte(txt), &doc) != nil {
		return nil
	}
	var servers map[string]any
	for _, k := range []string{"mcpServers", "servers"} {
		if m, ok := doc[k].(map[string]any); ok {
			servers = m
		}
	}
	var out []mcpServer
	for name, v := range servers {
		m, _ := v.(map[string]any)
		s := mcpServer{Name: name, Raw: m}
		if c, ok := m["command"].(string); ok {
			s.Cmd = c
		}
		if a, ok := m["args"].([]any); ok {
			for _, x := range a {
				s.Args = append(s.Args, fmt.Sprint(x))
			}
			s.Cmd = strings.TrimSpace(s.Cmd + " " + strings.Join(s.Args, " "))
		}
		if u, ok := m["url"].(string); ok && s.Cmd == "" {
			s.Cmd = u
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}
