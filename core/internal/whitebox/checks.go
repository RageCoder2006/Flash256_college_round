package whitebox

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/41vi4p/avhsol/core/internal/redact"
	"github.com/41vi4p/avhsol/core/internal/scengen"
)

type lineRule struct {
	ID, Sev, Title, Detail, Fix, Conf string
	Pat, Not                          *regexp.Regexp
	Langs                             map[string]bool // nil = any
	SkipTests                         bool
}

var lineRules = []lineRule{
	{ID: "WB-SHELL-SINK", Sev: "medium", Conf: "medium", Title: "Shell command execution", SkipTests: true,
		Detail: "Code runs shell commands. If any part of the command comes from the model or from content the model read, an injected instruction becomes code execution.",
		Fix:    "Pass arguments as a list (no shell), allow-list the commands, and run the agent in a sandbox.",
		Pat:    regexp.MustCompile(`(shell\s*=\s*True|os\.system\(|os\.popen\(|\bexecSync\(|child_process.*\bexec\(|\bexec\.Command\(\s*"(sh|bash)"|Runtime\.getRuntime\(\)\.exec)`)},
	{ID: "WB-EVAL-SINK", Sev: "high", Conf: "medium", Title: "Dynamic code evaluation", SkipTests: true,
		Detail: "eval/Function/exec on a string. Model output or fetched content reaching it is remote code execution.",
		Fix:    "Remove dynamic evaluation, or parse a restricted data format instead.",
		Pat:    regexp.MustCompile(`(^|[^\w.])eval\(|new Function\(|(^|[^\w.])exec\(\s*(f?["']|\w+\s*[,)])|vm\.runIn\w*Context\(`), Not: regexp.MustCompile(`(?i)(regex|\.exec\(|re\.|RegExp)`)},
	{ID: "WB-SQL-CONCAT", Sev: "medium", Conf: "medium", Title: "SQL built by string formatting", SkipTests: true,
		Detail: "A query is assembled from a string. If the model supplies the value, an injected instruction can read or change other rows.",
		Fix:    "Use parameterised queries and give the agent a read-only database role.",
		Pat:    regexp.MustCompile("(?i)(execute|query)\\(\\s*(f[\"']|[\"'][^\"']*(select|insert|update|delete)[^\"']*[\"']\\s*(%|\\+|\\.format)|`[^`]*(select|insert|update|delete)[^`]*\\$\\{)")},
	{ID: "WB-AUTO-APPROVE", Sev: "high", Conf: "medium", Title: "Permission or approval check switched off", SkipTests: true,
		Detail: "The code or its configuration disables the human-approval step. Every action the model proposes then runs, including ones an injected instruction asks for.",
		Fix:    "Keep approval on for writes, shell and network tools, or allow-list specific safe commands.",
		Pat:    regexp.MustCompile(`(?i)(bypassPermissions|dangerously[-_]skip[-_]permissions|allow_dangerous_code\s*[=:]\s*(True|true)|auto[_-]?approve\s*[=:]\s*(True|true)|--yolo|yolo[_-]?mode\s*[=:]\s*(true|True)|require_?approval\s*[=:]\s*(false|False))`)},
	{ID: "WB-TLS-OFF", Sev: "medium", Conf: "high", Title: "TLS certificate verification disabled", SkipTests: true,
		Detail: "Network calls skip certificate checks, so fetched content or model replies can be altered in transit.",
		Fix:    "Remove verify=False / rejectUnauthorized:false / InsecureSkipVerify.",
		Pat:    regexp.MustCompile(`(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0)`)},
	{ID: "WB-DESERIALIZE", Sev: "medium", Conf: "medium", Title: "Unsafe deserialisation", SkipTests: true,
		Detail: "pickle/yaml.load on data that can come from outside executes code while loading.",
		Fix:    "Use JSON or yaml.safe_load.",
		Pat:    regexp.MustCompile(`(pickle\.loads?\(|yaml\.load\(|marshal\.loads\()`), Not: regexp.MustCompile(`Loader\s*=\s*\w*Safe|safe_load`), Langs: map[string]bool{"Python": true}},
}

var secretPats = []*regexp.Regexp{
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,}\b`),
	regexp.MustCompile(`\bhf_[A-Za-z0-9]{20,}\b`),
	regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{12,}\b`),
	regexp.MustCompile(`\bsk-(ant-|proj-)?[A-Za-z0-9_-]{24,}\b`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(api[_-]?key|secret|token|passwd|password)["']?\s*[:=]\s*["'][A-Za-z0-9/+_\-]{20,}["']`),
}

var placeholderRe = regexp.MustCompile(`(?i)(your[_-]|example|xxxx|changeme|<[^>]+>|placeholder|dummy|\*{4,}|test|fake|sample)`)

type group struct {
	f     Finding
	count int
}

func maskLine(s string) string {
	s = strings.TrimSpace(s)
	out, _ := redact.Text(s, nil)
	if len(out) > 160 {
		out = out[:159] + "…"
	}
	return out
}

// runChecks applies the line rules, secret scan, instruction-file and MCP-config checks, and tool-level checks.
func runChecks(code []*file, other map[string]string, tools []Tool) []Finding {
	groups := map[string]*group{}
	order := []string{}
	put := func(f Finding) {
		key := f.ID + "|" + f.File
		if g, ok := groups[key]; ok {
			g.count++
			return
		}
		groups[key] = &group{f: f}
		order = append(order, key)
	}
	for _, f := range code {
		for i, ln := range f.Lines {
			t := strings.TrimSpace(ln)
			if t == "" {
				continue
			}
			if strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*") {
				continue // comments
			}
			for _, r := range lineRules {
				if r.Langs != nil && !r.Langs[f.Lang] {
					continue
				}
				if r.SkipTests && f.Test {
					continue
				}
				if r.Pat.MatchString(ln) && (r.Not == nil || !r.Not.MatchString(ln)) {
					sev := r.Sev
					put(Finding{ID: r.ID, Severity: sev, Title: r.Title, Detail: r.Detail, Fix: r.Fix, File: f.Rel, Line: i + 1, Evidence: maskLine(ln), Confidence: r.Conf})
				}
			}
			for _, sp := range secretPats {
				if m := sp.FindString(ln); m != "" && !placeholderRe.MatchString(ln) {
					sev, conf := "high", "high"
					if f.Test {
						sev, conf = "low", "medium"
					}
					fp := redact.Fingerprint(m)
					put(Finding{ID: "WB-SECRET", Severity: sev, Title: "Credential committed in source", Detail: "A credential-shaped value is in the code (fingerprint " + fp + "). Anyone with the repository, and any agent that reads it, has the key.",
						Fix: "Rotate it, remove it from history, and load it from the environment or a secret manager.", File: f.Rel, Line: i + 1, Evidence: maskLine(ln), Confidence: conf})
					break
				}
			}
		}
	}
	// committed .env files and instruction files
	var instr []string
	for rel, txt := range other {
		b := filepath.Base(rel)
		if strings.HasPrefix(b, ".env") && !strings.Contains(b, "example") && !strings.Contains(b, "sample") && !strings.Contains(b, "template") {
			for i, ln := range strings.Split(txt, "\n") {
				k, v, ok := strings.Cut(strings.TrimSpace(ln), "=")
				if ok && !strings.HasPrefix(k, "#") && len(strings.Trim(v, `"' `)) >= 8 && !placeholderRe.MatchString(v) {
					put(Finding{ID: "WB-ENV-COMMITTED", Severity: "high", Title: "Environment file with values in the repository", Detail: "A .env file with real-looking values sits in the tree; the agent can read it and so can anyone who clones the repository.",
						Fix: "Keep .env out of version control (.gitignore) and ship a .env.example without values.", File: rel, Line: i + 1, Evidence: k + "=[" + redact.Fingerprint(v) + "]", Confidence: "medium"})
					break
				}
			}
		}
		switch strings.ToLower(b) {
		case "agents.md", "claude.md", ".cursorrules", "gemini.md", "copilot-instructions.md":
			instr = append(instr, rel)
		}
		if isMCPConfig(rel) {
			for _, s := range mcpServers(txt) {
				cmd := strings.ToLower(s.Cmd)
				if (strings.Contains(cmd, "npx") && strings.Contains(cmd, "-y")) || strings.HasPrefix(cmd, "uvx ") || strings.Contains(cmd, "uvx ") {
					if !regexp.MustCompile(`@\d+\.\d+|==\d`).MatchString(cmd) {
						put(Finding{ID: "WB-MCP-UNPINNED", Severity: "medium", Title: "MCP server fetched and run without a pinned version", Detail: "Server " + s.Name + " is downloaded on start (" + clip(s.Cmd, 80) + "). A compromised or changed package becomes a new tool with the agent's permissions.",
							Fix: "Pin an exact version (package@1.2.3) or vendor the server.", File: rel, Line: 1, Evidence: clip(s.Cmd, 120), Confidence: "high"})
					}
				}
				for _, a := range s.Args {
					if a == "/" || a == "~" || a == "$HOME" || a == "${HOME}" || a == "/home" {
						put(Finding{ID: "WB-MCP-BROAD-FS", Severity: "high", Title: "MCP server given a very broad filesystem root", Detail: "Server " + s.Name + " can reach " + a + ", which includes keys and credentials.",
							Fix: "Give it only the project directory.", File: rel, Line: 1, Evidence: clip(s.Cmd, 120), Confidence: "high"})
					}
				}
			}
		}
	}
	if len(instr) > 0 {
		sort.Strings(instr)
		put(Finding{ID: "WB-INSTRUCTION-FILES", Severity: "info", Title: "The agent reads repository-authored instruction files", Detail: "Files such as " + strings.Join(instr, ", ") + " are read into the agent's context. Anything that can edit them (a pull request, a dependency, a compromised contributor) can steer the agent; this is the injection surface the dynamic attack plants payloads on.",
			Fix: "Review changes to these files like code, and treat instructions found in fetched or third-party content as data.", File: instr[0], Line: 1, Confidence: "high"})
	}
	// tool-level checks
	roles := map[string]bool{}
	for _, t := range tools {
		for _, r := range t.Roles {
			roles[r] = true
		}
		hasHint := func(h string) bool {
			for _, x := range t.Hints {
				if x == h {
					return true
				}
			}
			return false
		}
		if hasHint("shell") && t.Confidence != "low" {
			put(Finding{ID: "WB-TOOL-SHELL", Severity: "high", Title: "Tool " + t.Name + " runs commands", Detail: "A tool the model can call executes shell commands. Only the sandbox bounds what an injected command can do.",
				Fix: "Constrain it to an allow-list of commands, drop network access, and run the agent in a sandbox.", File: t.File, Line: t.Line, Confidence: t.Confidence})
		}
		if hasHint("eval") {
			put(Finding{ID: "WB-TOOL-EVAL", Severity: "high", Title: "Tool " + t.Name + " evaluates code", Detail: "A tool the model can call evaluates strings as code.", Fix: "Replace with a restricted interpreter or a fixed set of operations.", File: t.File, Line: t.Line, Confidence: t.Confidence})
		}
		destructive := false
		for _, r := range t.Roles {
			if r == scengen.RoleDestructive && !hasRole(t.Roles, scengen.RoleShell) {
				destructive = true
			}
		}
		if destructive && !hasHint("approval") && t.Source != "mcp-config" {
			put(Finding{ID: "WB-NO-APPROVAL", Severity: "medium", Title: "Tool " + t.Name + " changes things with no approval step visible", Detail: "No confirmation or permission check appears near this tool's code. If it exists elsewhere, ignore this.",
				Fix: "Ask the user before destructive actions the model proposes.", File: t.File, Line: t.Line, Confidence: "low"})
		}
	}
	if roles[scengen.RoleSensitiveRead] && roles[scengen.RoleUntrustedRead] && (roles[scengen.RoleEgress] || roles[scengen.RoleShell]) {
		var names []string
		for _, t := range tools {
			names = append(names, t.Name)
		}
		sort.Strings(names)
		put(Finding{ID: "WB-TRIFECTA", Severity: "critical", Title: "Lethal trifecta: private data, untrusted content and an outbound channel", Detail: "Together the tools (" + clip(strings.Join(names, ", "), 140) + ") can read private data, ingest content authored by outsiders, and send data out. One injected instruction in a document can exfiltrate the data.",
			Fix: "Remove one leg: stop the egress, isolate the sensitive reads, or make the untrusted reads a separate, tool-less agent.", Confidence: "medium"})
	}
	var out []Finding
	for _, k := range order {
		g := groups[k]
		g.f.Count = g.count
		out = append(out, g.f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if sevOrder[out[i].Severity] != sevOrder[out[j].Severity] {
			return sevOrder[out[i].Severity] < sevOrder[out[j].Severity]
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func hasRole(rs []string, r string) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}

// String is a one-line form for terminal output.
func (f Finding) String() string {
	loc := ""
	if f.File != "" {
		loc = fmt.Sprintf(" %s:%d", f.File, f.Line)
	}
	more := ""
	if f.Count > 0 {
		more = fmt.Sprintf(" (+%d more in this file)", f.Count)
	}
	return fmt.Sprintf("[%s] %s%s%s", strings.ToUpper(f.Severity), f.Title, loc, more)
}
