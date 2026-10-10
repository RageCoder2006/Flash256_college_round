package export

import (
	"fmt"
	"sort"
	"strings"

	"github.com/41vi4p/avhsol/core/internal/intel"
)

// IntelRef is a public advisory or paper related to a finding. Related means "describes the same kind of attack",
// never "proves the target has that bug".
type IntelRef struct {
	ID       string  `json:"id"`
	Source   string  `json:"source"`
	Title    string  `json:"title"`
	Severity string  `json:"severity,omitempty"`
	KEV      bool    `json:"kev,omitempty"`
	EPSS     float64 `json:"epss,omitempty"`
	URL      string  `json:"url,omitempty"`
	Why      string  `json:"why"`
}

// ThreatContext summarises the intel layer for the whole report.
type ThreatContext struct {
	CacheItems int        `json:"cache_items"`
	Taxonomy   string     `json:"taxonomy_version"`
	Refs       []IntelRef `json:"refs"`
	Note       string     `json:"note"`
}

const intelNote = "Advisories are matched to findings by attack technique. A match shows that this kind of attack has been reported against other software; it does not show the tested agent contains that vulnerability. Intel does not affect the risk rating, which comes only from the measured runs."

// attachIntel adds related public intel to each finding and a report-level threat context. A missing or empty
// cache simply means no section: the report never fails or blocks because intel is unavailable.
func attachIntel(r *Report, dir string) {
	if dir == "" {
		dir = intel.Dir()
	}
	st, err := intel.Open(dir)
	if err != nil || st.Count() == 0 {
		return
	}
	tax, _ := intel.LoadTaxonomy()
	seen := map[string]bool{}
	var all []IntelRef
	for i := range r.Findings {
		f := &r.Findings[i]
		var refs []IntelRef
		add := func(it intel.Item, why string) {
			for _, x := range refs {
				if x.ID == it.ID {
					return
				}
			}
			refs = append(refs, IntelRef{ID: it.ID, Source: it.Source, Title: it.Title, Severity: it.Severity, KEV: it.KEV, EPSS: it.EPSS, URL: it.URL, Why: why})
		}
		if f.IntelSeed != "" {
			if it, ok := st.Get(f.IntelSeed); ok {
				add(it, "the attack seed was derived from this item")
			}
		}
		items := st.Query(intel.Filter{Tag: "technique:" + f.Technique})
		sort.SliceStable(items, func(a, b int) bool { return intel.Rank(items[a]) > intel.Rank(items[b]) })
		for _, it := range items {
			if len(refs) >= 4 {
				break
			}
			if it.Kind == "paper" && len(refs) >= 3 {
				continue
			}
			add(it, "same technique: "+strings.ReplaceAll(f.Technique, "_", " "))
		}
		f.Intel = refs
		if tax != nil {
			f.Taxonomy = tax.IDs(f.Technique)
		}
		for _, x := range refs {
			if !seen[x.ID] {
				seen[x.ID] = true
				all = append(all, x)
			}
		}
	}
	if len(all) == 0 {
		return
	}
	sort.SliceStable(all, func(a, b int) bool {
		if all[a].KEV != all[b].KEV {
			return all[a].KEV
		}
		return all[a].EPSS > all[b].EPSS
	})
	if len(all) > 12 {
		all = all[:12]
	}
	tv := ""
	if tax != nil {
		tv = tax.Version
	}
	r.Threat = &ThreatContext{CacheItems: st.Count(), Taxonomy: tv, Refs: all, Note: intelNote}
	r.HasIntel = true
	_ = fmt.Sprint
}
