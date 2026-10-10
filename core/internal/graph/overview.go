package graph

import (
	"context"
	"fmt"
	"strings"
)

// Node keys are the ids the browser uses for graph nodes. Steps keep their own id ("tr-1234#7");
// every other kind is prefixed so ids never collide across kinds.
func nodeKey(kind, id string) string {
	switch kind {
	case "Episode":
		return "ep:" + id
	case "Payload":
		return "payload:" + id
	case "Resource":
		return "res:" + id
	case "Secret":
		return "secret:" + id
	case "Technique":
		return "tech:" + id
	case "Defense":
		return "def:" + id
	case "Tool":
		return "tool:" + id
	}
	return id // Step
}

// Overview is the whole constellation: the most recent episodes and everything they connect to.
// Steps are not included (there can be hundreds per run); the browser loads an episode's steps on demand.
func (s *Store) Overview(ctx context.Context, f Filter, maxEpisodes int) (*Subgraph, error) {
	if maxEpisodes < 1 || maxEpisodes > 80 {
		maxEpisodes = 24
	}
	fw, fp := f.where("e")
	fp["n"] = maxEpisodes
	eps, err := s.read(ctx, `
		MATCH (e:Episode) WHERE `+fw+`
		WITH e ORDER BY e.start_ms DESC LIMIT $n
		OPTIONAL MATCH (e)-[a:ASSESSED]->(o:Objective) WHERE a.rec_to IS NULL AND a.success = true AND o.severity = 'critical'
		WITH e, count(a) > 0 AS won
		OPTIONAL MATCH (e)-[:PLANTED]->(p:Payload)-[:INSTANCE_OF]->(t:Technique)
		OPTIONAL MATCH (p)-[:PLANTED_IN]->(res:Resource)
		RETURN e.id AS id, e.kind AS kind, e.guard_mode AS guard, e.scenario AS scenario, e.target AS target, e.start_ms AS start,
		       e.steps AS nsteps, won, p.id AS pid, left(p.text, 90) AS ptext, t.id AS tech, res.id AS rid, res.name AS rname`, fp)
	if err != nil {
		return nil, err
	}
	g := &Subgraph{}
	seen := map[string]bool{}
	node := func(n GNode) {
		if !seen[n.ID] {
			seen[n.ID] = true
			g.Nodes = append(g.Nodes, n)
		}
	}
	edge := func(a, b, t string) { g.Edges = append(g.Edges, GEdge{From: a, To: b, Type: t}) }
	var ids []any
	inSet := map[string]bool{}
	for _, r := range eps {
		id := asStr(r["id"])
		ids = append(ids, id)
		inSet[id] = true
		ek := nodeKey("Episode", id)
		label := id
		if i := strings.LastIndex(id, "-"); i >= 0 && len(id) > 8 {
			label = id[:3] + id[i+1:]
		}
		node(GNode{ID: ek, Kind: "episode", Label: label, Meta: map[string]any{
			"episode": id, "episode_kind": asStr(r["kind"]), "guard": asStr(r["guard"]), "scenario": asStr(r["scenario"]),
			"target": asStr(r["target"]), "achieved": r["won"] == true, "steps": asInt(r["nsteps"]), "start": asInt(r["start"])}})
		if pid := asStr(r["pid"]); pid != "" {
			pk := nodeKey("Payload", pid)
			node(GNode{ID: pk, Kind: "payload", Label: "payload", Flag: "untrusted", Meta: map[string]any{"text": asStr(r["ptext"])}})
			edge(ek, pk, "PLANTED")
			if t := asStr(r["tech"]); t != "" {
				tk := nodeKey("Technique", t)
				node(GNode{ID: tk, Kind: "technique", Label: strings.ReplaceAll(t, "_", " ")})
				edge(pk, tk, "INSTANCE_OF")
			}
			if rid := asStr(r["rid"]); rid != "" {
				rk := nodeKey("Resource", rid)
				node(GNode{ID: rk, Kind: "resource", Label: asStr(r["rname"])})
				edge(pk, rk, "PLANTED_IN")
			}
		}
	}
	if len(ids) == 0 {
		return g, nil
	}
	rows, err := s.read(ctx, `
		UNWIND $ids AS id
		MATCH (e:Episode {id:id})-[:HAS_STEP]->(:ToolCall)-[:INVOKES]->(t:Tool)
		RETURN DISTINCT id, t.id AS tool`, map[string]any{"ids": ids})
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		tk := nodeKey("Tool", asStr(r["tool"]))
		node(GNode{ID: tk, Kind: "tool", Label: asStr(r["tool"])})
		edge(nodeKey("Episode", asStr(r["id"])), tk, "USED")
	}
	rows, err = s.read(ctx, `
		UNWIND $ids AS id
		MATCH (e:Episode {id:id})-[:HAS_STEP]->(:Step)-[:LEAKED|EXPOSED]->(sec:Secret)
		RETURN DISTINCT id, sec.id AS sec`, map[string]any{"ids": ids})
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		sk := nodeKey("Secret", asStr(r["sec"]))
		node(GNode{ID: sk, Kind: "secret", Label: "secret " + clip(asStr(r["sec"]), 6), Flag: "leak"})
		edge(nodeKey("Episode", asStr(r["id"])), sk, "TOUCHED")
	}
	rows, err = s.read(ctx, `
		UNWIND $ids AS id
		MATCH (e:Episode {id:id})
		OPTIONAL MATCH (d:Defense)-[:STOPPED]->(e)
		OPTIONAL MATCH (e)-[:REPLAY_OF]->(o:Episode)
		RETURN id, collect(DISTINCT d.id) AS defs, collect(DISTINCT o.id) AS replays`, map[string]any{"ids": ids})
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		ek := nodeKey("Episode", asStr(r["id"]))
		if ds, ok := r["defs"].([]any); ok {
			for _, d := range ds {
				dk := nodeKey("Defense", asStr(d))
				node(GNode{ID: dk, Kind: "defense", Label: asStr(d), Flag: "blocked"})
				edge(dk, ek, "STOPPED")
			}
		}
		if os, ok := r["replays"].([]any); ok {
			for _, o := range os {
				if inSet[asStr(o)] {
					edge(ek, nodeKey("Episode", asStr(o)), "REPLAY_OF")
				}
			}
		}
	}
	return g, nil
}

// ---- spreading activation: which parts of the graph "light up" for a query ----

// Activation is how strongly one node is involved in a query's answer, from 0 to 1.
type Activation struct {
	ID    string  `json:"id"`
	Level float64 `json:"level"`
}

const decay = 0.6 // activation lost per hop away from a retrieved passage

type actMap map[string]float64

func (m actMap) bump(id string, lvl float64) {
	if lvl > m[id] {
		m[id] = lvl
	}
}

// Activate turns retrieved passages into an activation map. Each hit starts at a level set by its
// similarity score; activation then spreads along causal edges (what tainted what, what the guard
// judged, which secret was touched) up to two hops, fading by `decay` per hop. The owning episode,
// its payload, technique and the defenses that stopped it are lit more faintly.
func (s *Store) Activate(ctx context.Context, hits []SimilarHit) ([]Activation, error) {
	if len(hits) == 0 {
		return nil, nil
	}
	lo, hi := hits[0].Score, hits[0].Score
	for _, h := range hits {
		if h.Score < lo {
			lo = h.Score
		}
		if h.Score > hi {
			hi = h.Score
		}
	}
	base := func(sc float32) float64 {
		if hi == lo {
			return 1
		}
		return 0.55 + 0.45*float64(sc-lo)/float64(hi-lo)
	}
	m := actMap{}
	epLvl := map[string]float64{}
	var seeds []any
	for _, h := range hits {
		lvl := base(h.Score)
		switch h.Kind {
		case "step":
			id := fmt.Sprintf("%s#%d", h.Episode, h.Seq)
			m.bump(id, lvl)
			seeds = append(seeds, map[string]any{"id": id, "lvl": lvl})
			if lvl > epLvl[h.Episode] {
				epLvl[h.Episode] = lvl
			}
		case "payload":
			if h.PayloadID != "" {
				pk := nodeKey("Payload", h.PayloadID)
				m.bump(pk, lvl)
				rows, err := s.read(ctx, `MATCH (p:Payload {id:$p})<-[:PLANTED]-(e:Episode) RETURN e.id AS ep LIMIT 6`, map[string]any{"p": h.PayloadID})
				if err != nil {
					return nil, err
				}
				for _, r := range rows {
					if e := asStr(r["ep"]); lvl*0.7 > epLvl[e] {
						epLvl[e] = lvl * 0.7
					}
				}
			}
		}
	}
	if len(seeds) > 0 {
		rows, err := s.read(ctx, `
			UNWIND $seeds AS seed
			MATCH (st:Step {id: seed.id})
			OPTIONAL MATCH p=(st)-[:TAINTED_BY|RETURNED|EVALUATED|NEXT|READ|ACCESSED|LEAKED|EXPOSED|BY_RULE*1..2]-(n)
			WHERE n IS NULL OR n:Step OR n:Resource OR n:Secret OR n:Defense
			RETURN seed.lvl AS lvl, n.id AS nid, labels(n) AS nl, min(length(p)) AS d`, map[string]any{"seeds": seeds})
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			nid := asStr(r["nid"])
			if nid == "" {
				continue
			}
			kind := "Step"
			if ls, ok := r["nl"].([]any); ok {
				for _, l := range ls {
					switch asStr(l) {
					case "Resource", "Secret", "Defense":
						kind = asStr(l)
					}
				}
			}
			lvl := 1.0
			if f, ok := r["lvl"].(float64); ok {
				lvl = f
			}
			d := asInt(r["d"])
			m.bump(nodeKey(kind, nid), lvl*pow(decay, int(d)))
		}
	}
	if len(epLvl) > 0 {
		var ids []any
		for e := range epLvl {
			ids = append(ids, e)
		}
		rows, err := s.read(ctx, `
			UNWIND $ids AS id
			MATCH (e:Episode {id:id})
			OPTIONAL MATCH (e)-[:PLANTED]->(p:Payload)-[:INSTANCE_OF]->(t:Technique)
			OPTIONAL MATCH (d:Defense)-[:STOPPED]->(e)
			OPTIONAL MATCH (e)-[:REPLAY_OF]->(o:Episode)
			OPTIONAL MATCH (e)-[:HAS_STEP]->(:ToolCall)-[:INVOKES]->(tl:Tool)
			RETURN id, collect(DISTINCT p.id) AS payloads, collect(DISTINCT t.id) AS techs, collect(DISTINCT d.id) AS defs,
			       collect(DISTINCT o.id) AS replays, collect(DISTINCT tl.id) AS tools`, map[string]any{"ids": ids})
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			e := asStr(r["id"])
			l := epLvl[e]
			m.bump(nodeKey("Episode", e), 0.75*l)
			add := func(key string, kind string, f float64) {
				if xs, ok := r[key].([]any); ok {
					for _, x := range xs {
						if id := asStr(x); id != "" {
							m.bump(nodeKey(kind, id), f*l)
						}
					}
				}
			}
			add("payloads", "Payload", 0.6)
			add("techs", "Technique", 0.55)
			add("defs", "Defense", 0.65)
			add("replays", "Episode", 0.4)
			add("tools", "Tool", 0.3)
		}
	}
	out := make([]Activation, 0, len(m))
	for id, l := range m {
		if l >= 0.08 {
			out = append(out, Activation{ID: id, Level: l})
		}
	}
	return out, nil
}

func pow(b float64, n int) float64 {
	r := 1.0
	for i := 0; i < n; i++ {
		r *= b
	}
	return r
}
