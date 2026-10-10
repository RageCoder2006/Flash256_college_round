package graph

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/41vi4p/avhsol/core/internal/intel"
	"github.com/41vi4p/avhsol/core/internal/vec"
)

// Intel items live in their own Qdrant collection so they never mix into the evidence from recorded runs.
func (ix *Index) intelCollection() string { return ix.Collection + "_intel" }

// IngestIntel writes threat-intel items into the graph as :Intel nodes linked to the techniques they motivate,
// and (when an index is given) embeds their text so GraphRAG can cite them. Third-party text is clipped; it is
// stored as data and shown to a model only inside a block labelled as untrusted.
func (s *Store) IngestIntel(ctx context.Context, items []intel.Item, ix *Index) (int, error) {
	now := time.Now().UnixMilli()
	var stmts []stmt
	var vitems []intel.Item
	for _, it := range items {
		it.Clean()
		if it.ID == "" || it.Kind == "probe" {
			continue
		}
		stmts = append(stmts, stmt{`
			MERGE (i:Intel {id:$id})
			ON CREATE SET i.rec_from=$now
			SET i.source=$source, i.kind=$kind, i.title=$title, i.severity=$sev, i.cvss=$cvss, i.epss=$epss, i.kev=$kev, i.url=$url, i.modified=$mod`,
			map[string]any{"id": it.ID, "now": now, "source": it.Source, "kind": it.Kind, "title": it.Title, "sev": it.Severity,
				"cvss": it.CVSS, "epss": it.EPSS, "kev": it.KEV, "url": it.URL, "mod": it.Modified}})
		for _, tag := range it.Tags {
			if tech, ok := strings.CutPrefix(tag, "technique:"); ok {
				stmts = append(stmts, stmt{`
					MATCH (i:Intel {id:$id})
					MERGE (t:Technique {id:$tech}) ON CREATE SET t.name=$tech, t.rec_from=$now
					MERGE (i)-[:MOTIVATES]->(t)`, map[string]any{"id": it.ID, "tech": tech, "now": now}})
			}
		}
		vitems = append(vitems, it)
	}
	if len(stmts) == 0 {
		return 0, nil
	}
	for i := 0; i < len(stmts); i += 200 {
		j := i + 200
		if j > len(stmts) {
			j = len(stmts)
		}
		if err := s.write(ctx, stmts[i:j]); err != nil {
			return 0, err
		}
	}
	if ix != nil && len(vitems) > 0 {
		if err := ix.upsertIntel(ctx, vitems); err != nil {
			return len(vitems), fmt.Errorf("intel graph written, vectors failed: %w", err)
		}
	}
	return len(vitems), nil
}

func (ix *Index) upsertIntel(ctx context.Context, items []intel.Item) error {
	col := ix.intelCollection()
	if err := ix.Q.EnsureCollection(ctx, col, ix.Emb.Dim()); err != nil {
		return err
	}
	for i := 0; i < len(items); i += 64 {
		j := i + 64
		if j > len(items) {
			j = len(items)
		}
		texts := make([]string, 0, j-i)
		for _, it := range items[i:j] {
			texts = append(texts, it.Title+". "+it.Summary)
		}
		vs, err := ix.Emb.Embed(ctx, texts)
		if err != nil {
			return err
		}
		pts := make([]vec.Point, 0, j-i)
		for k, it := range items[i:j] {
			pts = append(pts, vec.Point{ID: "intel:" + it.Source + ":" + it.ID, Vector: vs[k], Payload: map[string]any{
				"kind": "intel", "intel_id": it.ID, "source": it.Source, "title": it.Title, "text": clip(it.Summary, 600),
				"severity": it.Severity, "kev": it.KEV, "epss": it.EPSS, "url": it.URL}})
		}
		if err := ix.Q.Upsert(ctx, col, pts); err != nil {
			return err
		}
	}
	return nil
}

// IntelHit is a threat-intel item close in meaning to a question or payload.
type IntelHit struct {
	Score    float32 `json:"score"`
	ID       string  `json:"id"`
	Source   string  `json:"source"`
	Title    string  `json:"title"`
	Text     string  `json:"text"`
	Severity string  `json:"severity,omitempty"`
	KEV      bool    `json:"kev,omitempty"`
	URL      string  `json:"url,omitempty"`
}

// SimilarIntel searches the intel collection. A missing collection (no intel ingested yet) is not an error.
func (s *Store) SimilarIntel(ctx context.Context, ix *Index, text string, k int) []IntelHit {
	vs, err := ix.Emb.Embed(ctx, []string{text})
	if err != nil {
		return nil
	}
	hits, err := ix.Q.Search(ctx, ix.intelCollection(), vs[0], k, nil)
	if err != nil {
		return nil
	}
	var out []IntelHit
	for _, h := range hits {
		kev, _ := h.Payload["kev"].(bool)
		out = append(out, IntelHit{Score: h.Score, ID: asStr(h.Payload["intel_id"]), Source: asStr(h.Payload["source"]), Title: asStr(h.Payload["title"]),
			Text: asStr(h.Payload["text"]), Severity: asStr(h.Payload["severity"]), KEV: kev, URL: asStr(h.Payload["url"])})
	}
	return out
}

// intelOverview adds the intel layer to an overview: :Intel nodes that motivate techniques already on screen,
// and the episodes that were inspired by them.
func (s *Store) intelOverview(ctx context.Context, g *Subgraph, seen map[string]bool, epIDs []any, limit int) error {
	var techs []any
	for _, n := range g.Nodes {
		if n.Kind == "technique" {
			techs = append(techs, strings.TrimPrefix(n.ID, "tech:"))
		}
	}
	rows, err := s.read(ctx, `
		MATCH (i:Intel)-[:MOTIVATES]->(t:Technique) WHERE t.id IN $techs
		WITH i, collect(DISTINCT t.id) AS ts
		ORDER BY coalesce(i.kev,false) DESC, coalesce(i.epss,0) DESC, coalesce(i.cvss,0) DESC LIMIT $lim
		RETURN i.id AS id, i.source AS source, i.title AS title, i.severity AS sev, i.kev AS kev, i.epss AS epss, i.url AS url, ts`,
		map[string]any{"techs": techs, "lim": limit})
	if err != nil {
		return err
	}
	for _, r := range rows {
		k := nodeKey("Intel", asStr(r["id"]))
		if !seen[k] {
			seen[k] = true
			g.Nodes = append(g.Nodes, GNode{ID: k, Kind: "intel", Label: asStr(r["id"]), Flag: map[bool]string{true: "kev"}[r["kev"] == true],
				Meta: map[string]any{"title": asStr(r["title"]), "source": asStr(r["source"]), "severity": asStr(r["sev"]), "url": asStr(r["url"]), "kev": r["kev"] == true, "epss": r["epss"]}})
		}
		if ts, ok := r["ts"].([]any); ok {
			for _, t := range ts {
				g.Edges = append(g.Edges, GEdge{From: k, To: nodeKey("Technique", asStr(t)), Type: "MOTIVATES"})
			}
		}
	}
	if len(epIDs) > 0 {
		rows, err = s.read(ctx, `UNWIND $ids AS id MATCH (e:Episode {id:id})-[:INSPIRED_BY]->(i:Intel) RETURN e.id AS ep, i.id AS intel`, map[string]any{"ids": epIDs})
		if err != nil {
			return err
		}
		for _, r := range rows {
			k := nodeKey("Intel", asStr(r["intel"]))
			if !seen[k] {
				seen[k] = true
				g.Nodes = append(g.Nodes, GNode{ID: k, Kind: "intel", Label: asStr(r["intel"])})
			}
			g.Edges = append(g.Edges, GEdge{From: nodeKey("Episode", asStr(r["ep"])), To: k, Type: "INSPIRED_BY"})
		}
	}
	return nil
}
