package export

import (
	"testing"

	"github.com/41vi4p/avhsol/core/internal/intel"
)

func TestAttachIntelMatchesByTechniqueAndNeverTouchesTheRating(t *testing.T) {
	dir := t.TempDir()
	st, _ := intel.Open(dir)
	tax, _ := intel.LoadTaxonomy()
	for _, it := range []intel.Item{
		{ID: "CVE-1", Source: "nvd", Kind: "cve", Title: "Prompt injection in agent", Summary: "ignore previous instructions", KEV: true},
		{ID: "CVE-2", Source: "nvd", Kind: "cve", Title: "Image codec overflow", Summary: "png"},
	} {
		tax.Annotate(&it)
		st.Upsert([]intel.Item{it})
	}
	_ = st.Save()
	r := &Report{RiskRating: "High", Findings: []Finding{{Technique: "instruction_override"}, {Technique: "roleplay", IntelSeed: "CVE-1"}}}
	attachIntel(r, dir)
	if !r.HasIntel || len(r.Findings[0].Intel) != 1 || r.Findings[0].Intel[0].ID != "CVE-1" {
		t.Fatalf("technique match failed: %+v", r.Findings[0].Intel)
	}
	if r.Findings[1].Intel[0].Why != "the attack seed was derived from this item" {
		t.Fatalf("seed provenance not first: %+v", r.Findings[1].Intel)
	}
	if r.RiskRating != "High" || r.Threat.Note == "" {
		t.Fatal("rating must be untouched and the caveat present")
	}
	empty := &Report{Findings: []Finding{{Technique: "x"}}}
	attachIntel(empty, t.TempDir())
	if empty.HasIntel {
		t.Fatal("an empty cache must produce no intel section")
	}
}
