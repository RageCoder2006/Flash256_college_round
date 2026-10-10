package graph

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// PathStep is one step of an episode annotated with its causal context.
type PathStep struct {
	Seq       int64    `json:"seq"`
	Type      string   `json:"type"`
	Name      string   `json:"name,omitempty"`
	Args      string   `json:"args,omitempty"`
	Content   string   `json:"content,omitempty"`
	Source    string   `json:"source,omitempty"`
	Decision  string   `json:"decision,omitempty"`
	Rules     []string `json:"rules,omitempty"`
	TaintedBy *int64   `json:"tainted_by,omitempty"`
	Secrets   []string `json:"secrets,omitempty"`
}

// Why returns an episode's steps with provenance: which untrusted read tainted each later call,
// what the guard decided about it, and which (fingerprinted) secrets it touched.
func (s *Store) Why(ctx context.Context, ep string) ([]PathStep, error) {
	rows, err := s.read(ctx, `
		MATCH (e:Episode {id:$ep})-[:HAS_STEP]->(st:Step)
		OPTIONAL MATCH (g:GuardDecision)-[ev:EVALUATED]->(st)
		OPTIONAL MATCH (st)-[:TAINTED_BY]->(i:Step)
		OPTIONAL MATCH (st)-[:LEAKED|EXPOSED]->(sec:Secret)
		RETURN st.seq AS seq, st.type AS type, st.name AS name, st.args AS args,
		       coalesce(st.content, st.text, st.reason, st.detail) AS content, st.source AS source,
		       coalesce(st.decision, ev.decision) AS decision, coalesce(st.rule_ids, g.rule_ids) AS rules,
		       i.seq AS tainted_by, collect(DISTINCT sec.id) AS secrets
		ORDER BY st.seq`, map[string]any{"ep": ep})
	if err != nil {
		return nil, err
	}
	var out []PathStep
	for _, r := range rows {
		p := PathStep{Seq: asInt(r["seq"]), Type: asStr(r["type"]), Name: asStr(r["name"]), Args: clip(asStr(r["args"]), 220),
			Content: clip(asStr(r["content"]), 160), Source: asStr(r["source"]), Decision: asStr(r["decision"])}
		if rs, ok := r["rules"].([]any); ok {
			for _, x := range rs {
				p.Rules = append(p.Rules, asStr(x))
			}
		}
		if v, ok := r["tainted_by"].(int64); ok {
			p.TaintedBy = &v
		}
		if ss, ok := r["secrets"].([]any); ok {
			for _, x := range ss {
				p.Secrets = append(p.Secrets, asStr(x))
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// Belief is one version of a verdict, with both time axes.
type Belief struct {
	Objective string `json:"objective"`
	Success   bool   `json:"success"`
	Evidence  string `json:"evidence"`
	ValidFrom int64  `json:"valid_from"`
	RecFrom   int64  `json:"rec_from"`
	RecTo     *int64 `json:"rec_to,omitempty"`
}

// Beliefs returns what AVHSOL held about an episode's verdicts, read through the given clock.
// With a zero Clock it is the current belief; with AsOf set it is what we believed then.
func (s *Store) Beliefs(ctx context.Context, ep string, c Clock) ([]Belief, error) {
	where, params := c.Where("a", Event)
	params["ep"] = ep
	rows, err := s.read(ctx, `
		MATCH (e:Episode {id:$ep})-[a:ASSESSED]->(o:Objective)
		WHERE `+where+`
		RETURN o.name AS objective, a.success AS success, a.evidence AS evidence, a.valid_from AS vf, a.rec_from AS rf, a.rec_to AS rt
		ORDER BY objective, a.rec_from`, params)
	if err != nil {
		return nil, err
	}
	var out []Belief
	for _, r := range rows {
		b := Belief{Objective: asStr(r["objective"]), Success: r["success"] == true, Evidence: asStr(r["evidence"]), ValidFrom: asInt(r["vf"]), RecFrom: asInt(r["rf"])}
		if v, ok := r["rt"].(int64); ok {
			b.RecTo = &v
		}
		out = append(out, b)
	}
	return out, nil
}

// History returns every version of every verdict of an episode (ignores the record axis on purpose).
func (s *Store) History(ctx context.Context, ep string) ([]Belief, error) {
	rows, err := s.read(ctx, `
		MATCH (e:Episode {id:$ep})-[a:ASSESSED]->(o:Objective)
		RETURN o.name AS objective, a.success AS success, a.evidence AS evidence, a.valid_from AS vf, a.rec_from AS rf, a.rec_to AS rt
		ORDER BY objective, a.rec_from`, map[string]any{"ep": ep})
	if err != nil {
		return nil, err
	}
	var out []Belief
	for _, r := range rows {
		b := Belief{Objective: asStr(r["objective"]), Success: r["success"] == true, Evidence: asStr(r["evidence"]), ValidFrom: asInt(r["vf"]), RecFrom: asInt(r["rf"])}
		if v, ok := r["rt"].(int64); ok {
			b.RecTo = &v
		}
		out = append(out, b)
	}
	return out, nil
}

// Filter narrows statistics. Simulated runs (the offline gullible model) are excluded unless asked
// for, because pooling them with real-model runs produces numbers that mean nothing.
type Filter struct {
	Scenario         string
	Target           string
	Model            string
	IncludeSimulated bool
}

// where returns a Cypher boolean over episode alias `e` and its parameters.
func (f Filter) where(e string) (string, map[string]any) {
	p := map[string]any{"f_sc": f.Scenario, "f_tg": f.Target, "f_md": f.Model}
	w := fmt.Sprintf("($f_sc = '' OR %[1]s.scenario = $f_sc) AND ($f_tg = '' OR %[1]s.target = $f_tg) AND ($f_md = '' OR %[1]s.model = $f_md)", e)
	if !f.IncludeSimulated {
		w += fmt.Sprintf(" AND coalesce(%s.simulated, false) = false", e)
	}
	return w, p
}

// TechniqueStat is how a technique has fared across all episodes, read through a clock.
type TechniqueStat struct {
	Technique string   `json:"technique"`
	Episodes  int64    `json:"episodes"`
	Succeeded int64    `json:"succeeded"`
	Rate      float64  `json:"rate"`
	StoppedBy []string `json:"stopped_by,omitempty"`
}

// Techniques aggregates attack outcomes per technique using the beliefs held at the clock's record time.
// An episode counts as succeeded if any objective of critical severity was achieved.
func (s *Store) Techniques(ctx context.Context, c Clock, f Filter) ([]TechniqueStat, error) {
	where, params := c.Where("a", Event)
	fw, fp := f.where("e")
	merge(params, fp)
	rows, err := s.read(ctx, `
		MATCH (e:Episode {kind:'attack'})-[:PLANTED]->(:Payload)-[:INSTANCE_OF]->(t:Technique)
		WHERE e.guard_mode = 'off' AND t.name <> 'control' AND `+fw+`
		OPTIONAL MATCH (e)-[a:ASSESSED]->(o:Objective) WHERE `+where+` AND a.success = true AND o.severity = 'critical'
		WITH t, e, count(a) > 0 AS won
		OPTIONAL MATCH (d:Defense)-[:STOPPED]->(:Episode)-[:REPLAY_OF]->(e)
		WITH t, e, won, collect(DISTINCT d.id) AS stoppers
		RETURN t.name AS technique, count(e) AS episodes, sum(CASE WHEN won THEN 1 ELSE 0 END) AS succeeded,
		       reduce(acc = [], x IN collect(stoppers) | acc + x) AS stoppers
		ORDER BY succeeded DESC, episodes DESC`, params)
	if err != nil {
		return nil, err
	}
	var out []TechniqueStat
	for _, r := range rows {
		ts := TechniqueStat{Technique: asStr(r["technique"]), Episodes: asInt64(r["episodes"]), Succeeded: asInt64(r["succeeded"])}
		if ts.Episodes > 0 {
			ts.Rate = float64(ts.Succeeded) / float64(ts.Episodes)
		}
		seen := map[string]bool{}
		if xs, ok := r["stoppers"].([]any); ok {
			for _, x := range xs {
				if id := asStr(x); id != "" && !seen[id] {
					seen[id] = true
					ts.StoppedBy = append(ts.StoppedBy, id)
				}
			}
		}
		sort.Strings(ts.StoppedBy)
		out = append(out, ts)
	}
	return out, nil
}

// Episodes lists recent episodes (current belief about success).
type EpisodeRow struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Scenario string `json:"scenario"`
	Target   string `json:"target"`
	Guard    string `json:"guard_mode"`
	Start    int64  `json:"start_ms"`
	Won      bool   `json:"critical_objective_achieved"`
}

func (s *Store) Episodes(ctx context.Context, limit int, f Filter) ([]EpisodeRow, error) {
	fw, fp := f.where("e")
	fp["n"] = limit
	rows, err := s.read(ctx, `
		MATCH (e:Episode) WHERE `+fw+`
		OPTIONAL MATCH (e)-[a:ASSESSED]->(o:Objective) WHERE a.rec_to IS NULL AND a.success = true AND o.severity = 'critical'
		WITH e, count(a) > 0 AS won
		RETURN e.id AS id, e.kind AS kind, e.scenario AS scenario, e.target AS target, e.guard_mode AS guard, e.start_ms AS start, won
		ORDER BY e.start_ms DESC LIMIT $n`, fp)
	if err != nil {
		return nil, err
	}
	var out []EpisodeRow
	for _, r := range rows {
		out = append(out, EpisodeRow{ID: asStr(r["id"]), Kind: asStr(r["kind"]), Scenario: asStr(r["scenario"]), Target: asStr(r["target"]),
			Guard: asStr(r["guard"]), Start: asInt(r["start"]), Won: r["won"] == true})
	}
	return out, nil
}

// FormatPath renders a provenance path for humans and for LLM context.
func FormatPath(steps []PathStep) string {
	var b strings.Builder
	for _, p := range steps {
		switch p.Type {
		case "user_turn":
			fmt.Fprintf(&b, "  #%d user asked: %s\n", p.Seq, clip(p.Content, 140))
		case "tool_call":
			fmt.Fprintf(&b, "  #%d CALL %s %s", p.Seq, p.Name, p.Args)
			if p.TaintedBy != nil {
				fmt.Fprintf(&b, "   <- tainted by #%d", *p.TaintedBy)
			}
			if len(p.Secrets) > 0 {
				fmt.Fprintf(&b, "   !! touches secret %s", strings.Join(p.Secrets, ","))
			}
			b.WriteString("\n")
		case "tool_result":
			if p.Source != "" {
				fmt.Fprintf(&b, "  #%d RESULT (untrusted: %s) %s\n", p.Seq, p.Source, p.Content)
			} else {
				fmt.Fprintf(&b, "  #%d RESULT %s", p.Seq, p.Content)
				if len(p.Secrets) > 0 {
					fmt.Fprintf(&b, "   !! shows secret %s", strings.Join(p.Secrets, ","))
				}
				b.WriteString("\n")
			}
		case "sandbox_event":
			fmt.Fprintf(&b, "  #%d SANDBOX %s\n", p.Seq, clip(p.Content, 140))
		case "guard":
			if p.Decision == "allow" {
				continue // an allow is the default; only show the interventions
			}
			fmt.Fprintf(&b, "  #%d GUARD %s %s  %s\n", p.Seq, strings.ToUpper(p.Decision), strings.Join(p.Rules, "+"), clip(p.Content, 110))
		}
	}
	return b.String()
}

func FormatTime(ms int64) string {
	if ms == 0 {
		return "-"
	}
	return time.UnixMilli(ms).UTC().Format("2006-01-02 15:04:05Z")
}

func asStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
func asInt(v any) int64 { return asInt64(v) }
func asInt64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	}
	return 0
}

// GNode / GEdge are a small, display-ready subgraph for one episode.
type GNode struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"` // step type, or payload / resource / secret / defense
	Label string `json:"label"`
	Seq   int64  `json:"seq"`
	Flag  string `json:"flag,omitempty"` // untrusted | blocked | leak
}

type GEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}

type Subgraph struct {
	Nodes []GNode `json:"nodes"`
	Edges []GEdge `json:"edges"`
}

// Subgraph returns the causal graph of one episode: steps, the provenance and guard edges between
// them, the planted payload, and the (fingerprinted) secrets and defenses involved.
func (s *Store) Subgraph(ctx context.Context, ep string) (*Subgraph, error) {
	g := &Subgraph{}
	seen := map[string]bool{}
	addNode := func(n GNode) {
		if !seen[n.ID] {
			seen[n.ID] = true
			g.Nodes = append(g.Nodes, n)
		}
	}
	steps, err := s.read(ctx, `
		MATCH (e:Episode {id:$ep})-[:HAS_STEP]->(st:Step)
		WHERE st.type IN ['user_turn','tool_call','tool_result','guard']
		RETURN st.id AS id, st.type AS type, st.seq AS seq, coalesce(st.name, '') AS name, coalesce(st.source, '') AS source,
		       coalesce(st.decision, '') AS decision, coalesce(left(st.args, 60), left(st.content, 60), left(st.text, 60), left(st.reason, 60), '') AS detail
		ORDER BY st.seq`, map[string]any{"ep": ep})
	if err != nil {
		return nil, err
	}
	for _, r := range steps {
		t := asStr(r["type"])
		label := asStr(r["name"])
		if label == "" {
			label = asStr(r["detail"])
		}
		n := GNode{ID: asStr(r["id"]), Kind: t, Label: clip(label, 48), Seq: asInt(r["seq"])}
		switch {
		case asStr(r["source"]) != "":
			n.Flag = "untrusted"
		case t == "guard" && asStr(r["decision"]) != "allow" && asStr(r["decision"]) != "":
			n.Flag = "blocked"
			n.Label = strings.ToUpper(asStr(r["decision"]))
		case t == "guard":
			n.Label = "ALLOW"
		}
		addNode(n)
	}
	edges, err := s.read(ctx, `
		MATCH (e:Episode {id:$ep})-[:HAS_STEP]->(a:Step)-[r:TAINTED_BY|RETURNED|EVALUATED|NEXT]->(b:Step)
		WHERE a.type IN ['user_turn','tool_call','tool_result','guard'] AND b.type IN ['user_turn','tool_call','tool_result','guard']
		RETURN a.id AS a, b.id AS b, type(r) AS t`, map[string]any{"ep": ep})
	if err != nil {
		return nil, err
	}
	for _, r := range edges {
		if seen[asStr(r["a"])] && seen[asStr(r["b"])] {
			g.Edges = append(g.Edges, GEdge{From: asStr(r["a"]), To: asStr(r["b"]), Type: asStr(r["t"])})
		}
	}
	extra, err := s.read(ctx, `
		MATCH (e:Episode {id:$ep})
		OPTIONAL MATCH (e)-[:PLANTED]->(p:Payload)-[:PLANTED_IN]->(res:Resource)
		OPTIONAL MATCH (e)-[:HAS_STEP]->(x:Step)-[:READ]->(res)
		OPTIONAL MATCH (e)-[:HAS_STEP]->(l:Step)-[lk:LEAKED|EXPOSED]->(sec:Secret)
		RETURN p.id AS pid, left(p.text, 50) AS ptext, res.id AS rid, res.name AS rname, x.id AS readstep, l.id AS lstep, type(lk) AS lt, sec.id AS sid`, map[string]any{"ep": ep})
	if err != nil {
		return nil, err
	}
	for _, r := range extra {
		if pid := asStr(r["pid"]); pid != "" {
			addNode(GNode{ID: "payload:" + pid, Kind: "payload", Label: "payload", Flag: "untrusted"})
			if rid := asStr(r["rid"]); rid != "" {
				addNode(GNode{ID: "res:" + rid, Kind: "resource", Label: asStr(r["rname"])})
				g.Edges = append(g.Edges, GEdge{From: "payload:" + pid, To: "res:" + rid, Type: "PLANTED_IN"})
				if rs := asStr(r["readstep"]); rs != "" && seen[rs] {
					g.Edges = append(g.Edges, GEdge{From: rs, To: "res:" + rid, Type: "READ"})
				}
			}
		}
		if sid := asStr(r["sid"]); sid != "" {
			addNode(GNode{ID: "secret:" + sid, Kind: "secret", Label: "secret " + sid[:6], Flag: "leak"})
			if ls := asStr(r["lstep"]); ls != "" && seen[ls] {
				g.Edges = append(g.Edges, GEdge{From: ls, To: "secret:" + sid, Type: asStr(r["lt"])})
			}
		}
	}
	// de-duplicate edges
	uniq := map[GEdge]bool{}
	var out []GEdge
	for _, e := range g.Edges {
		if !uniq[e] {
			uniq[e] = true
			out = append(out, e)
		}
	}
	g.Edges = out
	return g, nil
}
