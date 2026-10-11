package whitebox

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// frameworkSigs: a name found in a manifest or an import line identifies the framework.
var frameworkSigs = []struct {
	Name string
	Pat  *regexp.Regexp
}{
	{"OpenAI SDK", regexp.MustCompile(`(?i)(^|[\s"'/@(])(openai)([\s"'=<>~^,)]|$)`)},
	{"Anthropic SDK", regexp.MustCompile(`(?i)(@anthropic-ai/sdk|(^|[\s"'])anthropic([\s"'=<>~^,)]|$))`)},
	{"LangChain", regexp.MustCompile(`(?i)(langchain|@langchain/)`)},
	{"LangGraph", regexp.MustCompile(`(?i)langgraph`)},
	{"LlamaIndex", regexp.MustCompile(`(?i)llama[-_]index`)},
	{"CrewAI", regexp.MustCompile(`(?i)crewai`)},
	{"AutoGen", regexp.MustCompile(`(?i)(autogen|ag2)`)},
	{"OpenAI Agents SDK", regexp.MustCompile(`(?i)(openai-agents|from agents import|@openai/agents)`)},
	{"Claude Agent SDK", regexp.MustCompile(`(?i)(claude-agent-sdk|claude_agent_sdk|@anthropic-ai/claude-code)`)},
	{"Vercel AI SDK", regexp.MustCompile(`(?i)(["']ai["']\s*:|from ["']ai["']|@ai-sdk/)`)},
	{"MCP", regexp.MustCompile(`(?i)(@modelcontextprotocol/sdk|(^|[\s"'])mcp([\s"'=<>~^,\[)]|$)|fastmcp|mcp\.server)`)},
	{"pi", regexp.MustCompile(`(?i)(@earendil-works/pi|pi-monorepo|pi-coding-agent)`)},
	{"Ollama", regexp.MustCompile(`(?i)ollama`)},
	{"Hugging Face", regexp.MustCompile(`(?i)(transformers|smolagents|huggingface[-_]hub)`)},
}

func detect(code []*file, other map[string]string) (langs, frameworks []string) {
	count := map[string]int{}
	for _, f := range code {
		count[f.Lang]++
	}
	type lc struct {
		l string
		n int
	}
	var ls []lc
	for l, n := range count {
		ls = append(ls, lc{l, n})
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i].n > ls[j].n })
	for _, x := range ls {
		langs = append(langs, x.l)
	}
	seen := map[string]bool{}
	scan := func(text string) {
		for _, s := range frameworkSigs {
			if !seen[s.Name] && s.Pat.MatchString(text) {
				seen[s.Name] = true
			}
		}
	}
	for rel, txt := range other {
		if isManifest(baseName(rel)) && !strings.HasSuffix(rel, "lock.json") && !strings.HasSuffix(rel, ".lock") {
			scan(manifestNames(rel, txt))
		}
	}
	for _, f := range code {
		if f.Test {
			continue
		}
		for i, ln := range f.Lines {
			if i > 80 { // imports sit at the top
				break
			}
			t := strings.TrimSpace(ln)
			if strings.HasPrefix(t, "import ") || strings.HasPrefix(t, "from ") || strings.Contains(t, "require(") || strings.Contains(t, " from \"") || strings.Contains(t, " from '") {
				scan(t)
			}
		}
	}
	for _, s := range frameworkSigs {
		if seen[s.Name] {
			frameworks = append(frameworks, s.Name)
		}
	}
	return
}

func baseName(rel string) string {
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		return rel[i+1:]
	}
	return rel
}

// manifestNames reduces a manifest to the names it mentions (so a description word never counts as a dependency).
func manifestNames(rel, txt string) string {
	if baseName(rel) == "package.json" {
		var pj struct {
			Name         string            `json:"name"`
			Dependencies map[string]string `json:"dependencies"`
			Dev          map[string]string `json:"devDependencies"`
			Peer         map[string]string `json:"peerDependencies"`
		}
		if json.Unmarshal([]byte(txt), &pj) == nil {
			var b strings.Builder
			b.WriteString(`"` + pj.Name + "\"\n")
			for _, m := range []map[string]string{pj.Dependencies, pj.Dev, pj.Peer} {
				for k := range m {
					b.WriteString(`"` + k + "\"\n")
				}
			}
			return b.String()
		}
	}
	return txt
}
