package intel

import (
	"sort"
	"strings"
)

// SourceInfo describes one data source for display: what it is, whether it needs a key, and how it last did.
type SourceInfo struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Role        string `json:"role"` // advisories | cves | enricher | research | taxonomy
	URL         string `json:"url"`
	Description string `json:"description"`
	KeyEnv      string `json:"key_env,omitempty"`
	KeySet      bool   `json:"key_set"`
	Items       int    `json:"items"`
	LastSync    string `json:"last_sync,omitempty"`
	Error       string `json:"error,omitempty"`
}

var catalog = []SourceInfo{
	{Name: "ghsa", Title: "GitHub Security Advisories", Role: "advisories", URL: "https://github.com/advisories", KeyEnv: "AVHSOL_GITHUB_TOKEN",
		Description: "Reviewed advisories for pip, npm, Go, Rust and Maven. Kept when the text is about agents or LLM tooling, or the package is on the agent-stack watchlist."},
	{Name: "nvd", Title: "NIST National Vulnerability Database", Role: "cves", URL: "https://nvd.nist.gov", KeyEnv: "AVHSOL_NVD_API_KEY",
		Description: "CVE records found by keyword: prompt injection, MCP, LLM agents, LangChain and similar."},
	{Name: "osv", Title: "OSV.dev", Role: "advisories", URL: "https://osv.dev",
		Description: "Open-source vulnerability database, queried for the packages that make up typical agent stacks (the watchlist)."},
	{Name: "kev", Title: "CISA Known Exploited Vulnerabilities", Role: "enricher", URL: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
		Description: "Marks cached CVEs that are being exploited in the wild. Adds no items of its own."},
	{Name: "epss", Title: "FIRST EPSS", Role: "enricher", URL: "https://www.first.org/epss",
		Description: "Probability that a CVE is exploited in the next 30 days. Adds no items of its own."},
	{Name: "feeds", Title: "Research feeds (arXiv)", Role: "research", URL: "https://arxiv.org",
		Description: "Recent papers on prompt injection, agent security and MCP. Leads for attack ideas, never findings."},
}

// Sources returns the catalog with live counts and sync state. Items for source "feeds" are those whose source starts with "feed:".
func (s *Store) Sources() []SourceInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts := map[string]int{}
	for _, it := range s.items {
		src := it.Source
		if strings.HasPrefix(src, "feed:") {
			src = "feeds"
		}
		counts[src]++
	}
	out := make([]SourceInfo, 0, len(catalog))
	for _, c := range catalog {
		c.Items = counts[c.Name]
		if c.Role == "enricher" {
			c.Items = 0
			for _, it := range s.items {
				if (c.Name == "kev" && it.KEV) || (c.Name == "epss" && it.EPSS > 0) {
					c.Items++
				}
			}
		}
		if st, ok := s.State.Sources[c.Name]; ok {
			c.LastSync, c.Error = st.LastSync, st.Error
		}
		out = append(out, c)
	}
	return out
}

// Facets counts items by kind, severity and technique, for filter chips and summary tiles.
type Facets struct {
	Total      int            `json:"total"`
	Kinds      map[string]int `json:"kinds"`
	Severity   map[string]int `json:"severity"`
	Techniques map[string]int `json:"techniques"`
	KEV        int            `json:"kev"`
	Taxonomy   string         `json:"taxonomy_version"`
}

func (s *Store) Facets() Facets {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := Facets{Kinds: map[string]int{}, Severity: map[string]int{}, Techniques: map[string]int{}}
	for _, it := range s.items {
		f.Total++
		f.Kinds[it.Kind]++
		if it.Severity != "" {
			f.Severity[it.Severity]++
		}
		if it.KEV {
			f.KEV++
		}
		for _, t := range it.Tags {
			if x, ok := strings.CutPrefix(t, "technique:"); ok {
				f.Techniques[x]++
			}
		}
	}
	if tax, err := LoadTaxonomy(); err == nil {
		f.Taxonomy = tax.Version
	}
	return f
}

// GNode / GEdge mirror the dashboard's graph payload shape.
type GNode struct {
	ID    string         `json:"id"`
	Kind  string         `json:"kind"`
	Label string         `json:"label"`
	Seq   int            `json:"seq"`
	Flag  string         `json:"flag,omitempty"`
	Meta  map[string]any `json:"meta,omitempty"`
}

type GEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}

type Graph struct {
	Nodes []GNode `json:"nodes"`
	Edges []GEdge `json:"edges"`
	Shown int     `json:"shown"`
	Total int     `json:"total_matching"`
}

// ItemNodeID is the graph id of an item.
func ItemNodeID(it Item) string { return "intel:" + it.Source + ":" + it.ID }

// BuildGraph makes the threat-intelligence knowledge graph from the cache: advisories and CVEs, the data source each came
// from, the attack techniques they point at, the taxonomy ids those map to, the packages they affect, and links between
// records that describe the same vulnerability. It reads only the local cache.
func BuildGraph(st *Store, f Filter, max int) Graph {
	if max < 1 || max > 400 {
		max = 150
	}
	f.Limit = 0
	all := st.Query(f)
	g := Graph{Total: len(all)}
	if len(all) > max {
		all = all[:max]
	}
	tax, _ := LoadTaxonomy()
	seen := map[string]bool{}
	node := func(n GNode) {
		if !seen[n.ID] {
			seen[n.ID] = true
			g.Nodes = append(g.Nodes, n)
		}
	}
	edge := func(a, b, t string) { g.Edges = append(g.Edges, GEdge{From: a, To: b, Type: t}) }
	pkgCount := map[string]int{}
	for _, it := range all {
		for _, a := range it.Affects {
			pkgCount[a]++
		}
	}
	byAlias := map[string][]string{}
	for _, it := range all {
		id := ItemNodeID(it)
		flag := it.Severity
		if it.KEV {
			flag = "kev"
		}
		node(GNode{ID: id, Kind: "intel", Label: it.ID, Flag: flag, Meta: map[string]any{
			"title": it.Title, "summary": clipRunes(it.Summary, 420), "source": it.Source, "item_kind": it.Kind, "severity": it.Severity,
			"cvss": it.CVSS, "epss": it.EPSS, "kev": it.KEV, "url": it.URL, "published": it.Published, "affects": it.Affects, "taxon": it.Taxon}})
		src := it.Source
		if strings.HasPrefix(src, "feed:") {
			src = "feeds"
		}
		node(GNode{ID: "src:" + src, Kind: "source", Label: src})
		edge(id, "src:"+src, "FROM_SOURCE")
		for _, tag := range it.Tags {
			if t, ok := strings.CutPrefix(tag, "technique:"); ok {
				node(GNode{ID: "tech:" + t, Kind: "technique", Label: strings.ReplaceAll(t, "_", " ")})
				edge(id, "tech:"+t, "MOTIVATES")
				if tax != nil {
					for _, x := range tax.IDs(t) {
						node(GNode{ID: "taxon:" + x, Kind: "taxon", Label: x, Meta: map[string]any{"family": taxonFamily(x)}})
						edge("tech:"+t, "taxon:"+x, "MAPS_TO")
					}
				}
			}
		}
		n := 0
		for _, a := range it.Affects {
			if pkgCount[a] >= 1 && n < 3 {
				node(GNode{ID: "pkg:" + a, Kind: "package", Label: a})
				edge(id, "pkg:"+a, "AFFECTS")
				n++
			}
		}
		for _, al := range append([]string{it.ID}, it.Aliases...) {
			if cveRe.MatchString(al) {
				byAlias[cveRe.FindString(al)] = append(byAlias[cveRe.FindString(al)], id)
			}
		}
	}
	done := map[string]bool{}
	var keys []string
	for k := range byAlias {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ids := uniqStr(byAlias[k])
		for i := 1; i < len(ids); i++ {
			key := ids[0] + ">" + ids[i]
			if !done[key] {
				done[key] = true
				edge(ids[0], ids[i], "ALIAS_OF")
			}
		}
	}
	g.Shown = len(all)
	return g
}

func taxonFamily(id string) string {
	switch {
	case strings.HasPrefix(id, "LLM"):
		return "OWASP LLM"
	case strings.HasPrefix(id, "ASI"):
		return "OWASP agentic"
	case strings.HasPrefix(id, "AML"):
		return "MITRE ATLAS"
	}
	return ""
}

func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func uniqStr(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
