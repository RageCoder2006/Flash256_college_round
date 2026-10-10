// Package intel collects public threat intelligence about AI agents (advisories, CVEs, exploited-vulnerability
// lists, taxonomies, research) into a local store. Nothing here runs during a test: sync is an explicit,
// audited command, and everything the platform uses later is read from the local cache.
//
// All text in an Item comes from third parties. It is clipped, stripped of control characters, and must be
// treated as DATA: it is never an instruction to the platform or to any model that reads it.
package intel

import (
	"net/url"
	"sort"
	"strings"
	"unicode"
)

// Item is one piece of intelligence, normalised across sources.
type Item struct {
	ID        string   `json:"id"`     // GHSA-xxxx, CVE-xxxx, GHSA/OSV id, arXiv id, ...
	Source    string   `json:"source"` // ghsa | nvd | osv | kev | arxiv | feed:<name> | taxonomy
	Kind      string   `json:"kind"`   // advisory | cve | paper | probe | technique
	Title     string   `json:"title"`
	Summary   string   `json:"summary"`
	URL       string   `json:"url,omitempty"`
	Published string   `json:"published,omitempty"` // RFC3339
	Modified  string   `json:"modified,omitempty"`
	Severity  string   `json:"severity,omitempty"` // critical | high | medium | low | ""
	CVSS      float64  `json:"cvss,omitempty"`
	EPSS      float64  `json:"epss,omitempty"` // probability of exploitation in the next 30 days, 0..1
	KEV       bool     `json:"kev,omitempty"`  // on CISA's known-exploited list
	Aliases   []string `json:"aliases,omitempty"`
	Affects   []string `json:"affects,omitempty"` // ecosystem:package
	Tags      []string `json:"tags,omitempty"`    // agent-relevance tags we derived
	Taxon     []string `json:"taxon,omitempty"`   // OWASP-LLM / ASI / ATLAS ids we mapped
}

// Key identifies an item across syncs.
func (i *Item) Key() string { return i.Source + ":" + i.ID }

const (
	maxTitle   = 200
	maxSummary = 1200
)

// Clean makes third-party text safe to store and print: no control characters, bounded length.
func (i *Item) Clean() {
	i.Title = cleanText(i.Title, maxTitle)
	i.Summary = cleanText(i.Summary, maxSummary)
	i.ID = cleanText(i.ID, 80)
	if u, err := url.Parse(i.URL); err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		i.URL = ""
	}
	i.Severity = strings.ToLower(cleanText(i.Severity, 12))
	i.Tags = uniq(i.Tags)
	i.Taxon = uniq(i.Taxon)
	i.Aliases = uniq(i.Aliases)
	i.Affects = uniq(i.Affects)
}

func cleanText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return ' '
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r): // includes zero-width and Unicode tag characters
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) > n {
		s = string([]rune(s)[:n-1]) + "…"
	}
	return s
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// agentKeywords decide whether a general vulnerability record is about AI agents or their tooling.
var agentKeywords = []string{
	"prompt injection", "indirect prompt", "jailbreak", "model context protocol", "mcp server", "mcp client", " mcp ", "mcp-",
	"llm", "large language model", "ai agent", "agentic", "coding agent", "langchain", "langgraph", "llamaindex", "llama-index",
	"autogen", "crewai", "openai", "anthropic", "claude", "copilot", "cursor", "codex", "gemini", "ollama", "vllm", "agent sdk",
	"tool poisoning", "tool call", "function calling", "rag ", "retrieval-augmented", "vector database", "ai assistant",
}

// Relevance returns the agent-related tags found in the item's text (empty = not about agents).
func Relevance(i *Item) []string {
	text := " " + strings.ToLower(i.Title+" "+i.Summary+" "+strings.Join(i.Affects, " ")) + " "
	var tags []string
	for _, k := range agentKeywords {
		if strings.Contains(text, k) {
			tags = append(tags, strings.TrimSpace(k))
		}
	}
	return uniq(tags)
}

// Topics maps text to the attack techniques AVHSOL knows, so intel can be matched to seeds and findings.
var topicWords = map[string][]string{
	"instruction_override":    {"prompt injection", "ignore previous", "instruction override", "indirect prompt"},
	"hidden_unicode":          {"unicode", "invisible", "zero-width", "tag characters", "hidden text", "hidden instruction"},
	"fence_forging":           {"delimiter", "boundary", "spoof", "system prompt injection", "role confusion"},
	"authority_impersonation": {"impersonat", "spoof", "trusted source", "social engineering"},
	"task_embedding":          {"poisoned", "malicious readme", "repository", "config file", "rules file", ".cursorrules", "agents.md"},
	"sandbox_escape":          {"sandbox escape", "path traversal", "arbitrary file read", "escape", "symlink"},
	"data_exfiltration":       {"exfiltrat", "data leak", "sensitive information", "markdown image", "ssrf", "credential"},
	"tool_poisoning":          {"tool poisoning", "malicious mcp", "mcp server", "tool description", "rug pull"},
	"excessive_agency":        {"excessive agency", "arbitrary command", "remote code execution", "command injection", "auto-run", "without confirmation"},
}

// TechniquesOf lists the AVHSOL techniques an item's text points at.
func TechniquesOf(i *Item) []string {
	text := strings.ToLower(i.Title + " " + i.Summary)
	var out []string
	for t, ws := range topicWords {
		for _, w := range ws {
			if strings.Contains(text, w) {
				out = append(out, t)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}
