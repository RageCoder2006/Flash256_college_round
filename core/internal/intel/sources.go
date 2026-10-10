package intel

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Source fetches items changed since a time. Sources never write to the store themselves.
type Source interface {
	Name() string
	Fetch(ctx context.Context, c *Client, since time.Time) ([]Item, error)
}

// Enricher adds facts (exploitation status, probability) to items already in the store.
type Enricher interface {
	Name() string
	Enrich(ctx context.Context, c *Client, s *Store) (int, error)
}

var cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

func sevFromCVSS(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	}
	return ""
}

// ---------------------------------------------------------------- GitHub Security Advisories

// GHSA reads the GitHub Advisory Database (reviewed advisories) and keeps those about agent tooling.
type GHSA struct {
	Base       string // default https://api.github.com
	Token      string // optional; raises the rate limit
	Ecosystems []string
	MaxPages   int
	Watch      *Watchlist
	Pause      time.Duration
}

func (g *GHSA) Name() string { return "ghsa" }

type ghsaAdvisory struct {
	GHSAID      string `json:"ghsa_id"`
	CVEID       string `json:"cve_id"`
	HTMLURL     string `json:"html_url"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	PublishedAt string `json:"published_at"`
	UpdatedAt   string `json:"updated_at"`
	CVSS        struct {
		Score float64 `json:"score"`
	} `json:"cvss"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
	} `json:"vulnerabilities"`
}

func (g *GHSA) Fetch(ctx context.Context, c *Client, since time.Time) ([]Item, error) {
	base := strings.TrimRight(orStr(g.Base, "https://api.github.com"), "/")
	pages := g.MaxPages
	if pages == 0 {
		pages = 5
	}
	eco := g.Ecosystems
	if len(eco) == 0 {
		eco = []string{"pip", "npm", "go", "rust", "maven"}
	}
	hdr := map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
	if g.Token != "" {
		hdr["Authorization"] = "Bearer " + g.Token
	}
	var out []Item
	seen := map[string]bool{}
	for _, e := range eco {
		q := url.Values{"type": {"reviewed"}, "ecosystem": {e}, "per_page": {"100"}, "sort": {"updated"}, "direction": {"desc"}}
		if !since.IsZero() {
			q.Set("modified", ">="+since.UTC().Format("2006-01-02"))
		}
		next := base + "/advisories?" + q.Encode()
		for p := 0; p < pages && next != ""; p++ {
			var list []ghsaAdvisory
			h, err := c.getJSON(ctx, next, hdr, &list)
			if err != nil {
				return out, fmt.Errorf("ghsa %s: %w", e, err)
			}
			for _, a := range list {
				if seen[a.GHSAID] {
					continue
				}
				seen[a.GHSAID] = true
				it := Item{ID: a.GHSAID, Source: "ghsa", Kind: "advisory", Title: a.Summary, Summary: a.Description, URL: a.HTMLURL,
					Published: a.PublishedAt, Modified: a.UpdatedAt, Severity: a.Severity, CVSS: a.CVSS.Score}
				if a.CVEID != "" {
					it.Aliases = append(it.Aliases, a.CVEID)
				}
				for _, v := range a.Vulnerabilities {
					it.Affects = append(it.Affects, v.Package.Ecosystem+":"+v.Package.Name)
				}
				if len(Relevance(&it)) == 0 && !g.Watch.MatchesAny(it.Affects) {
					continue // a general vulnerability, not about agents
				}
				out = append(out, it)
			}
			next = nextLink(h.Get("Link"))
			sleep(ctx, g.Pause)
		}
	}
	return out, nil
}

var linkRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func nextLink(h string) string {
	if m := linkRe.FindStringSubmatch(h); m != nil {
		return m[1]
	}
	return ""
}

// ---------------------------------------------------------------- NVD

// NVD queries the National Vulnerability Database CVE API 2.0 by keyword.
type NVD struct {
	Base     string // default https://services.nvd.nist.gov
	APIKey   string // optional; raises the rate limit
	Keywords []string
	Pause    time.Duration // NVD allows 5 requests per 30 s without a key
}

func (n *NVD) Name() string { return "nvd" }

var defaultNVDKeywords = []string{"prompt injection", "model context protocol", "MCP server", "LLM agent", "langchain", "AI coding assistant", "large language model"}

type nvdResp struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			CISAAdded    string `json:"cisaExploitAdd"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				V31 []struct {
					Data struct {
						Score    float64 `json:"baseScore"`
						Severity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func (n *NVD) Fetch(ctx context.Context, c *Client, since time.Time) ([]Item, error) {
	base := strings.TrimRight(orStr(n.Base, "https://services.nvd.nist.gov"), "/")
	kws := n.Keywords
	if len(kws) == 0 {
		kws = defaultNVDKeywords
	}
	end := time.Now().UTC()
	start := since
	if start.IsZero() || end.Sub(start) > 119*24*time.Hour { // the API limits a modified-date window to 120 days
		start = end.Add(-119 * 24 * time.Hour)
	}
	hdr := map[string]string{}
	if n.APIKey != "" {
		hdr["apiKey"] = n.APIKey
	}
	var out []Item
	seen := map[string]bool{}
	for _, kw := range kws {
		q := url.Values{"keywordSearch": {kw}, "lastModStartDate": {start.Format("2006-01-02T15:04:05.000")}, "lastModEndDate": {end.Format("2006-01-02T15:04:05.000")}, "resultsPerPage": {"100"}}
		var r nvdResp
		if _, err := c.getJSON(ctx, base+"/rest/json/cves/2.0?"+q.Encode(), hdr, &r); err != nil {
			return out, fmt.Errorf("nvd %q: %w", kw, err)
		}
		for _, v := range r.Vulnerabilities {
			cv := v.CVE
			if seen[cv.ID] {
				continue
			}
			seen[cv.ID] = true
			it := Item{ID: cv.ID, Source: "nvd", Kind: "cve", Published: cv.Published, Modified: cv.LastModified, URL: "https://nvd.nist.gov/vuln/detail/" + cv.ID, KEV: cv.CISAAdded != ""}
			for _, d := range cv.Descriptions {
				if d.Lang == "en" {
					it.Summary = d.Value
				}
			}
			it.Title = firstSentence(it.Summary)
			if len(cv.Metrics.V31) > 0 {
				it.CVSS = cv.Metrics.V31[0].Data.Score
				it.Severity = strings.ToLower(cv.Metrics.V31[0].Data.Severity)
			}
			out = append(out, it)
		}
		sleep(ctx, n.Pause)
	}
	return out, nil
}

func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i > 20 && i < 160 {
		return s[:i+1]
	}
	return s
}

// ---------------------------------------------------------------- OSV

// OSV looks up the agent-stack watchlist in osv.dev, then fetches details for the vulnerabilities found.
type OSV struct {
	Base       string // default https://api.osv.dev
	Watch      *Watchlist
	MaxDetails int
	Pause      time.Duration
}

func (o *OSV) Name() string { return "osv" }

type osvVuln struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Published string   `json:"published"`
	Modified  string   `json:"modified"`
	Severity  []struct {
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

func (o *OSV) Fetch(ctx context.Context, c *Client, since time.Time) ([]Item, error) {
	if o.Watch == nil || len(o.Watch.Packages) == 0 {
		return nil, fmt.Errorf("osv: the watchlist is empty")
	}
	base := strings.TrimRight(orStr(o.Base, "https://api.osv.dev"), "/")
	max := o.MaxDetails
	if max == 0 {
		max = 150
	}
	type pkg struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	}
	type q struct {
		Package pkg `json:"package"`
	}
	var queries []q
	for _, p := range o.Watch.Packages {
		queries = append(queries, q{pkg{p.Name, p.Ecosystem}})
	}
	var batch struct {
		Results []struct {
			Vulns []struct {
				ID       string `json:"id"`
				Modified string `json:"modified"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := c.postJSON(ctx, base+"/v1/querybatch", map[string]any{"queries": queries}, &batch); err != nil {
		return nil, fmt.Errorf("osv querybatch: %w", err)
	}
	var out []Item
	seen := map[string]bool{}
	for _, r := range batch.Results {
		for _, v := range r.Vulns {
			if seen[v.ID] || len(seen) >= max {
				continue
			}
			seen[v.ID] = true
			if m, err := time.Parse(time.RFC3339, v.Modified); err == nil && !since.IsZero() && m.Before(since) {
				continue
			}
			var d osvVuln
			if _, err := c.getJSON(ctx, base+"/v1/vulns/"+url.PathEscape(v.ID), nil, &d); err != nil {
				continue // one bad record must not lose the rest
			}
			it := Item{ID: d.ID, Source: "osv", Kind: "advisory", Title: d.Summary, Summary: d.Details, URL: "https://osv.dev/vulnerability/" + d.ID,
				Published: d.Published, Modified: d.Modified, Aliases: d.Aliases, Severity: d.DatabaseSpecific.Severity}
			if it.Title == "" {
				it.Title = firstSentence(d.Details)
			}
			for _, a := range d.Affected {
				it.Affects = append(it.Affects, a.Package.Ecosystem+":"+a.Package.Name)
			}
			it.Tags = append(it.Tags, "watchlist")
			out = append(out, it)
			sleep(ctx, o.Pause)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- CISA KEV (enricher)

// KEV marks stored items whose CVE is on CISA's Known Exploited Vulnerabilities list.
type KEV struct{ URL string }

func (k *KEV) Name() string { return "kev" }

func (k *KEV) Enrich(ctx context.Context, c *Client, s *Store) (int, error) {
	u := orStr(k.URL, "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	var cat struct {
		Vulns []struct {
			CVE string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if _, err := c.getJSON(ctx, u, nil, &cat); err != nil {
		return 0, fmt.Errorf("kev: %w", err)
	}
	set := map[string]bool{}
	for _, v := range cat.Vulns {
		set[v.CVE] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, it := range s.items {
		if it.KEV {
			continue
		}
		for _, id := range append([]string{it.ID}, it.Aliases...) {
			if set[id] {
				it.KEV = true
				it.Tags = uniq(append(it.Tags, "kev"))
				n++
				break
			}
		}
	}
	return n, nil
}

// ---------------------------------------------------------------- EPSS (enricher)

// EPSS adds FIRST's exploit-prediction score to items that have a CVE id.
type EPSS struct{ Base string }

func (e *EPSS) Name() string { return "epss" }

func (e *EPSS) Enrich(ctx context.Context, c *Client, s *Store) (int, error) {
	base := strings.TrimRight(orStr(e.Base, "https://api.first.org"), "/")
	s.mu.Lock()
	byCVE := map[string][]*Item{}
	for _, it := range s.items {
		for _, id := range append([]string{it.ID}, it.Aliases...) {
			if cveRe.MatchString(id) {
				byCVE[cveRe.FindString(id)] = append(byCVE[cveRe.FindString(id)], it)
			}
		}
	}
	s.mu.Unlock()
	var ids []string
	for id := range byCVE {
		ids = append(ids, id)
	}
	n := 0
	for i := 0; i < len(ids); i += 50 {
		j := i + 50
		if j > len(ids) {
			j = len(ids)
		}
		var r struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		if _, err := c.getJSON(ctx, base+"/data/v1/epss?cve="+url.QueryEscape(strings.Join(ids[i:j], ",")), nil, &r); err != nil {
			return n, fmt.Errorf("epss: %w", err)
		}
		s.mu.Lock()
		for _, d := range r.Data {
			var v float64
			if _, err := fmt.Sscanf(d.EPSS, "%f", &v); err == nil {
				for _, it := range byCVE[d.CVE] {
					it.EPSS = v
					n++
				}
			}
		}
		s.mu.Unlock()
	}
	return n, nil
}

// ---------------------------------------------------------------- research feeds (arXiv Atom)

// Feeds reads Atom feeds (arXiv API queries by default) for research on agent security. These are leads for
// seed ideas, not vulnerabilities, so they are stored as Kind "paper".
type Feeds struct {
	Feeds []FeedSpec
}

type FeedSpec struct {
	Name string `yaml:"name" json:"name"`
	URL  string `yaml:"url" json:"url"`
}

func (f *Feeds) Name() string { return "feeds" }

type atomFeed struct {
	Entries []struct {
		ID        string `xml:"id"`
		Title     string `xml:"title"`
		Summary   string `xml:"summary"`
		Published string `xml:"published"`
		Updated   string `xml:"updated"`
		Links     []struct {
			Href string `xml:"href,attr"`
		} `xml:"link"`
	} `xml:"entry"`
}

func (f *Feeds) Fetch(ctx context.Context, c *Client, since time.Time) ([]Item, error) {
	var out []Item
	var firstErr error
	for _, fs := range f.Feeds {
		b, _, err := c.do(ctx, "GET", fs.URL, nil, map[string]string{"Accept": "application/atom+xml, application/xml"})
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("feed %s: %w", fs.Name, err)
			}
			continue
		}
		var a atomFeed
		dec := xml.NewDecoder(strings.NewReader(string(b)))
		dec.Strict = false
		dec.Entity = xml.HTMLEntity
		if err := dec.Decode(&a); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("feed %s: %w", fs.Name, err)
			}
			continue
		}
		for _, e := range a.Entries {
			it := Item{ID: lastPathPart(e.ID), Source: "feed:" + fs.Name, Kind: "paper", Title: e.Title, Summary: e.Summary, Published: e.Published, Modified: e.Updated}
			if len(e.Links) > 0 {
				it.URL = e.Links[0].Href
			}
			if len(Relevance(&it)) == 0 {
				continue
			}
			out = append(out, it)
		}
	}
	return out, firstErr
}

func lastPathPart(s string) string {
	s = strings.TrimRight(s, "/")
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ---------------------------------------------------------------- watchlist

// Watchlist names the packages that make up an agent stack; OSV is queried for them and GHSA hits on them are kept.
type Watchlist struct {
	Packages []WatchPkg `yaml:"packages" json:"packages"`
}

type WatchPkg struct {
	Ecosystem string `yaml:"ecosystem" json:"ecosystem"`
	Name      string `yaml:"name" json:"name"`
}

// MatchesAny reports whether any "ecosystem:name" (GHSA/OSV spelling, case-insensitive) is on the list.
func (w *Watchlist) MatchesAny(affects []string) bool {
	if w == nil {
		return false
	}
	for _, a := range affects {
		for _, p := range w.Packages {
			if strings.EqualFold(a, p.Ecosystem+":"+p.Name) || strings.EqualFold(strings.SplitN(a, ":", 2)[len(strings.SplitN(a, ":", 2))-1], p.Name) {
				return true
			}
		}
	}
	return false
}

func readFileIf(path string) ([]byte, bool) {
	b, err := os.ReadFile(path)
	return b, err == nil
}
