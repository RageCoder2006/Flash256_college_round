package export

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/41vi4p/avhsol/core/internal/brand"
)

// SARIF renders findings as SARIF 2.1.0 so CI systems and code-scanning dashboards can ingest them.
func SARIF(r *Report) ([]byte, error) {
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string         `json:"id"`
		Name             string         `json:"name"`
		ShortDescription msg            `json:"shortDescription"`
		FullDescription  msg            `json:"fullDescription"`
		Properties       map[string]any `json:"properties,omitempty"`
	}
	rules := map[string]rule{}
	var results []map[string]any
	for _, f := range r.Findings {
		rid := "AVHSOL/" + f.Technique
		if _, ok := rules[rid]; !ok {
			rules[rid] = rule{ID: rid, Name: strings.ReplaceAll(f.Technique, "_", " "),
				ShortDescription: msg{"Agent hijacked by " + strings.ReplaceAll(f.Technique, "_", " ")},
				FullDescription:  msg{"An agent followed instructions planted in content it read and achieved a critical objective (for example leaking a credential). Detected by a deterministic check on planted canary data."},
				Properties:       map[string]any{"tags": append([]string{"security", "ai-agent"}, f.ASI...)}}
		}
		fp := sha256.Sum256([]byte(strings.Join([]string{r.Scenario, r.Target, f.SeedID, f.Surface, f.Operator}, "|")))
		text := fmt.Sprintf("%s. Achieved in %d of %d runs. %s", f.Title, f.Successes, f.Runs, f.Evidence)
		res := map[string]any{
			"ruleId": rid, "level": "error", "message": msg{text},
			"locations":           []map[string]any{{"logicalLocations": []map[string]any{{"name": r.Target, "fullyQualifiedName": r.Scenario + "/" + r.Target + "/" + f.Surface, "kind": "module"}}}},
			"partialFingerprints": map[string]string{"avhsolFinding/v1": hex.EncodeToString(fp[:12])},
			"properties": map[string]any{
				"traceId": f.TraceID, "reliability": f.Reliability, "runs": f.Runs, "owasp_agentic": f.ASI, "stopped_by": f.StoppedBy,
				"guardedReplays": f.GuardedRuns, "guardedReplaysStillSucceeding": f.GuardedSucceeded,
				"relatedIntel": intelIDs(f.Intel), "taxonomy": f.Taxonomy,
			},
		}
		results = append(results, res)
	}
	var ids []string
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var rs []rule
	for _, id := range ids {
		rs = append(rs, rules[id])
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool":    map[string]any{"driver": map[string]any{"name": brand.Name, "fullName": brand.Banner(), "version": brand.Version, "rules": rs}},
			"results": results,
			"properties": map[string]any{"simulated": r.Simulated, "scenario": r.Scenario, "target": r.Target, "model": r.Model,
				"validRuns": r.ValidRuns, "erroredRuns": r.ErroredRuns, "reportSha256": r.Integrity.ReportDigest},
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

// JSON is the full report.
func JSON(r *Report) ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

func intelIDs(refs []IntelRef) []string {
	var out []string
	for _, r := range refs {
		out = append(out, r.ID)
	}
	return out
}
