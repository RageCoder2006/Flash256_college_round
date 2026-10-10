package graph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/41vi4p/avhsol/core/internal/redact"
	"github.com/41vi4p/avhsol/core/internal/scenario"
	"github.com/41vi4p/avhsol/core/internal/trace"
	"github.com/41vi4p/avhsol/core/internal/vec"
)

// Index is the vector side; nil disables vector indexing.
type Index struct {
	Q          *vec.Qdrant
	Emb        vec.Embedder
	Collection string
}

type IngestStats struct {
	Steps      int  `json:"steps"`
	Vectors    int  `json:"vectors"`
	Redactions int  `json:"redactions"`
	Unchanged  bool `json:"unchanged"`
}

var stepLabel = map[string]string{
	trace.StepUserTurn:    "UserTurn",
	trace.StepLLMResponse: "LlmResponse",
	trace.StepToolCall:    "ToolCall",
	trace.StepToolResult:  "ToolResult",
	trace.StepGuard:       "GuardDecision",
	trace.StepSandbox:     "SandboxEvent",
	trace.StepKernel:      "KernelEvent",
}

func str(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func isUntrustedSource(src string) bool {
	return strings.HasPrefix(src, "retrieved:") || strings.HasPrefix(src, "web:") || strings.HasPrefix(src, "memory:")
}

func resourceName(src string) string {
	_, name, _ := strings.Cut(src, ":")
	return name
}

var volatile = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`127\.0\.0\.1:\d+`), "127.0.0.1:PORT"},
	{regexp.MustCompile(`avhsol-gw:\d+`), "avhsol-gw:PORT"},
	{regexp.MustCompile(`/tmp/avhsol-(host|ep)-\d+`), "/tmp/avhsol-$1-N"},
	{regexp.MustCompile(`tr-[0-9a-f]{8}`), "tr-ID"},
}

// payloadID identifies a payload by what it says, ignoring per-run details (sink port, temp paths),
// so a guarded replay of an exploit points at the same Payload node as the original run.
func payloadID(text string) string {
	for _, v := range volatile {
		text = v.re.ReplaceAllString(text, v.with)
	}
	h := sha256.Sum256([]byte(text))
	return hex.EncodeToString(h[:8])
}

// jsonStr renders a value as JSON for display. HTML escaping is off: a shell command with && must
// read as "&&" in the graph, not "\u0026\u0026".
func jsonStr(v any) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimSpace(b.String())
}

// IngestTrace writes one trace into the graph (and vectors). It is idempotent: ingesting the same
// trace again changes nothing, and a trace id re-used with different content is refused.
func (s *Store) IngestTrace(ctx context.Context, tr *trace.Trace, sc *scenario.Scenario, ix *Index) (IngestStats, error) {
	var stats IngestStats
	if err := tr.Verify(); err != nil {
		return stats, fmt.Errorf("refusing to ingest a trace whose hash chain is broken: %w", err)
	}
	head := tr.HeadHash()
	if rows, err := s.read(ctx, "MATCH (e:Episode {id:$id}) RETURN e.trace_head AS head", map[string]any{"id": tr.TraceID}); err == nil && len(rows) > 0 {
		if h, _ := rows[0]["head"].(string); h == head {
			stats.Unchanged = true
			return stats, nil
		}
		return stats, fmt.Errorf("trace id %s already exists with different content (head %s vs %s)", tr.TraceID, rows[0]["head"], head)
	}

	now := time.Now().UnixMilli()
	var known []string
	if sc != nil {
		known = sc.Canaries()
	}
	red := func(s string) string {
		out, n := redact.Text(s, known)
		stats.Redactions += n
		return out
	}
	scName := tr.ScenarioID
	agentID := scName + "/" + orStr(tr.Target, "unknown-target")
	startMs := tr.StartedAt.UnixMilli()
	endMs := startMs + tr.DurationMs

	var stmts []stmt
	stmts = append(stmts, stmt{`
		MERGE (ag:Agent {id:$agent_id}) ON CREATE SET ag.name=$agent_name, ag.rec_from=$now
		MERGE (e:Episode {id:$ep})
		ON CREATE SET e.kind=$kind, e.scenario=$scenario, e.model=$model, e.target=$agent_name, e.guard_mode=$guard,
		              e.start_ms=$start, e.end_ms=$end, e.valid_from=$start, e.valid_to=$end, e.rec_from=$now,
		              e.trace_head=$head, e.steps=$nsteps, e.final_text=$final, e.error=$err, e.policy=$policy,
		              e.success_at_ingest=$success, e.progress_at_ingest=$progress, e.simulated=$simulated, e.signed_by=$signed_by,
		              e.fork_of=$fork_of, e.fork_at=$fork_at, e.isolation=$isolation, e.observability=$observability
		MERGE (e)-[:TARGETS]->(ag)`,
		map[string]any{"agent_id": agentID, "agent_name": orStr(tr.Target, "unknown-target"), "ep": tr.TraceID, "kind": tr.Kind,
			"scenario": scName, "model": tr.Model, "guard": tr.GuardMode, "start": startMs, "end": endMs, "now": now,
			"head": head, "nsteps": len(tr.Steps), "final": red(clip(tr.FinalText, 2000)), "err": clip(tr.Error, 500),
			"policy": tr.PolicyHash, "success": tr.Success, "progress": tr.Progress,
			"simulated": tr.Model == "offline-simulated", "signed_by": signerOf(tr),
			"fork_of": nullable(tr.ForkOf), "fork_at": tr.ForkAt, "isolation": tr.Isolation, "observability": tr.Observability}})

	// ---- steps ----
	byLabel := map[string][]any{}
	var nextPairs, invokes, returned, resRead, accessed, tainted, evaluated, byRule, leaked, exposed []any
	callStep := map[string]string{} // tool_call_id -> step id
	var lastIngest string
	var texts []vecItem
	for _, st := range tr.Steps {
		id := fmt.Sprintf("%s#%d", tr.TraceID, st.Seq)
		label, ok := stepLabel[st.Type]
		if !ok {
			label = "Step"
		}
		d := st.Data
		props := map[string]any{"ep": tr.TraceID, "seq": st.Seq, "type": st.Type, "hash": st.Hash}
		var embedText string
		switch st.Type {
		case trace.StepUserTurn:
			props["text"] = red(clip(str(d, "text"), 1500))
			embedText = props["text"].(string)
		case trace.StepLLMResponse:
			props["text"] = red(clip(str(d, "text"), 1500))
			props["stop_reason"] = str(d, "stop_reason")
			embedText = props["text"].(string)
		case trace.StepToolCall:
			name := str(d, "name")
			args := red(clip(jsonStr(d["args"]), 2000))
			props["name"], props["args"], props["call_id"] = name, args, str(d, "id")
			callStep[str(d, "id")] = id
			invokes = append(invokes, map[string]any{"id": id, "tool": name})
			if m, ok := d["args"].(map[string]any); ok {
				for _, k := range []string{"doc_id", "path", "url"} {
					if v := str(m, k); v != "" {
						accessed = append(accessed, map[string]any{"id": id, "res": scName + "/" + baseName(v), "kind": k})
					}
				}
			}
			for _, c := range known {
				if c != "" && strings.Contains(jsonStr(d["args"]), c) {
					leaked = append(leaked, map[string]any{"id": id, "fp": redact.Fingerprint(c)})
				}
			}
			if lastIngest != "" {
				tainted = append(tainted, map[string]any{"id": id, "via": lastIngest})
			}
			embedText = "tool " + name + " " + args
		case trace.StepToolResult:
			src := str(d, "source")
			content := red(clip(str(d, "content"), 2000))
			props["content"], props["source"], props["call_id"] = content, src, str(d, "id")
			props["is_error"], _ = d["is_error"].(bool)
			if cs, ok := callStep[str(d, "id")]; ok {
				returned = append(returned, map[string]any{"call": cs, "result": id})
			}
			if isUntrustedSource(src) {
				lastIngest = id
				resRead = append(resRead, map[string]any{"id": id, "res": scName + "/" + resourceName(src), "src": src})
			}
			for _, c := range known {
				if c != "" && strings.Contains(str(d, "content"), c) {
					exposed = append(exposed, map[string]any{"id": id, "fp": redact.Fingerprint(c)})
				}
			}
			embedText = clip(content, 600)
		case trace.StepGuard:
			props["decision"], props["reason"], props["mode"] = str(d, "decision"), clip(str(d, "reason"), 600), str(d, "mode")
			var rules []string
			if rs, ok := d["rule_ids"].([]any); ok {
				for _, r := range rs {
					if x, ok := r.(string); ok {
						rules = append(rules, x)
						byRule = append(byRule, map[string]any{"id": id, "rule": x})
					}
				}
			}
			props["rule_ids"] = rules
			if cs, ok := callStep[str(d, "id")]; ok {
				evaluated = append(evaluated, map[string]any{"guard": id, "call": cs, "decision": str(d, "decision")})
			}
			embedText = "guard " + str(d, "decision") + " " + str(d, "reason")
		case trace.StepSandbox:
			props["event"] = str(d, "event")
			props["detail"] = red(clip(jsonStr(d), 800))
		}
		byLabel[label] = append(byLabel[label], map[string]any{"id": id, "seq": st.Seq, "ts": st.TS, "props": props})
		if st.Seq > 0 {
			nextPairs = append(nextPairs, map[string]any{"a": fmt.Sprintf("%s#%d", tr.TraceID, st.Seq-1), "b": id})
		}
		if strings.TrimSpace(embedText) != "" && st.Type != trace.StepSandbox {
			texts = append(texts, vecItem{id: id, text: embedText, payload: map[string]any{"kind": "step", "ep": tr.TraceID, "seq": st.Seq, "step_type": st.Type, "ts": st.TS}})
		}
		stats.Steps++
	}
	for label, rows := range byLabel {
		stmts = append(stmts, stmt{fmt.Sprintf(`
			MATCH (e:Episode {id:$ep})
			UNWIND $rows AS r
			MERGE (st:Step:%s {id:r.id})
			ON CREATE SET st += r.props, st.valid_from=r.ts, st.valid_to=r.ts, st.rec_from=$now
			MERGE (e)-[:HAS_STEP {seq:r.seq}]->(st)`, label), map[string]any{"ep": tr.TraceID, "rows": rows, "now": now}})
	}
	add := func(q string, rows []any) {
		if len(rows) > 0 {
			stmts = append(stmts, stmt{q, map[string]any{"rows": rows, "ep": tr.TraceID, "sc": scName, "now": now}})
		}
	}
	add(`UNWIND $rows AS r MATCH (a:Step {id:r.a}),(b:Step {id:r.b}) MERGE (a)-[:NEXT]->(b)`, nextPairs)
	add(`UNWIND $rows AS r MATCH (c:Step {id:r.id}) MERGE (t:Tool {id:r.tool}) ON CREATE SET t.name=r.tool, t.rec_from=$now MERGE (c)-[:INVOKES]->(t)`, invokes)
	add(`UNWIND $rows AS r MATCH (c:Step {id:r.call}),(x:Step {id:r.result}) MERGE (c)-[:RETURNED]->(x)`, returned)
	add(`UNWIND $rows AS r MATCH (x:Step {id:r.id}) MERGE (res:Resource {id:r.res}) ON CREATE SET res.name=split(r.res,'/')[-1], res.scenario=$sc, res.rec_from=$now MERGE (x)-[:READ {source:r.src}]->(res)`, resRead)
	add(`UNWIND $rows AS r MATCH (c:Step {id:r.id}) MERGE (res:Resource {id:r.res}) ON CREATE SET res.name=split(r.res,'/')[-1], res.scenario=$sc, res.rec_from=$now MERGE (c)-[:ACCESSED {via:r.kind}]->(res)`, accessed)
	add(`UNWIND $rows AS r MATCH (c:Step {id:r.id}),(i:Step {id:r.via}) MERGE (c)-[:TAINTED_BY]->(i)`, tainted)
	add(`UNWIND $rows AS r MATCH (g:Step {id:r.guard}),(c:Step {id:r.call}) MERGE (g)-[:EVALUATED {decision:r.decision}]->(c)`, evaluated)
	add(`UNWIND $rows AS r MATCH (g:Step {id:r.id}) MERGE (d:Defense {id:r.rule}) ON CREATE SET d.rec_from=$now MERGE (g)-[:BY_RULE]->(d)`, byRule)
	add(`UNWIND $rows AS r MATCH (c:Step {id:r.id}) MERGE (s:Secret {id:r.fp}) ON CREATE SET s.rec_from=$now MERGE (c)-[:LEAKED]->(s)`, leaked)
	add(`UNWIND $rows AS r MATCH (x:Step {id:r.id}) MERGE (s:Secret {id:r.fp}) ON CREATE SET s.rec_from=$now MERGE (x)-[:EXPOSED]->(s)`, exposed)

	// ---- payload / technique ----
	if a := tr.Attack; a != nil {
		pid := payloadID(a.Payload)
		ptxt := red(clip(a.Payload, 3000))
		stmts = append(stmts, stmt{`
			MATCH (e:Episode {id:$ep})
			MERGE (p:Payload {id:$pid}) ON CREATE SET p.text=$text, p.seed=$seed, p.operator=$op, p.rec_from=$now
			MERGE (t:Technique {id:$tech}) ON CREATE SET t.name=$tech, t.rec_from=$now
			MERGE (p)-[:INSTANCE_OF]->(t)
			MERGE (res:Resource {id:$res}) ON CREATE SET res.name=$surface, res.scenario=$sc, res.rec_from=$now
			MERGE (p)-[:PLANTED_IN]->(res)
			MERGE (e)-[:PLANTED]->(p)`,
			map[string]any{"ep": tr.TraceID, "pid": pid, "text": ptxt, "seed": a.SeedID, "op": a.Encoding, "now": now,
				"tech": a.Technique, "res": scName + "/" + baseName(a.Surface), "surface": a.Surface, "sc": scName}})
		if a.IntelRef != "" {
			stmts = append(stmts, stmt{`
				MATCH (e:Episode {id:$ep})
				MERGE (i:Intel {id:$ref}) ON CREATE SET i.rec_from=$now, i.stub=true
				MERGE (e)-[:INSPIRED_BY]->(i)`, map[string]any{"ep": tr.TraceID, "ref": a.IntelRef, "now": now}})
		}
		texts = append(texts, vecItem{id: "payload:" + pid, text: ptxt, payload: map[string]any{"kind": "payload", "ep": tr.TraceID, "technique": a.Technique, "seed": a.SeedID, "operator": a.Encoding, "payload_id": pid}})
	}

	// ---- verdicts: beliefs on the record axis; a changed verdict supersedes the old one ----
	for _, v := range tr.Verdicts {
		stmts = append(stmts, supersedeVerdict(tr.TraceID, scName, v, startMs, now, red(clip(v.Evidence, 500))))
	}
	for i, f := range tr.Findings {
		stmts = append(stmts, stmt{`
			MATCH (e:Episode {id:$ep})
			MERGE (f:Finding {id:$id}) ON CREATE SET f.kind=$kind, f.severity=$sev, f.tool=$tool, f.detail=$detail, f.valid_from=$vf, f.rec_from=$now
			MERGE (e)-[:RAISED]->(f)`,
			map[string]any{"ep": tr.TraceID, "id": fmt.Sprintf("%s#f%d", tr.TraceID, i), "kind": f.Kind, "sev": f.Severity, "tool": f.Tool, "detail": red(clip(f.Detail, 500)), "vf": startMs, "now": now}})
	}

	if err := s.write(ctx, stmts); err != nil {
		return stats, err
	}

	// ---- vectors (after the graph commit, so a vector never points at a missing node) ----
	if ix != nil && len(texts) > 0 {
		n, err := ix.upsert(ctx, tr, texts, scName)
		stats.Vectors = n
		if err != nil {
			return stats, fmt.Errorf("graph written, vector indexing failed: %w", err)
		}
	}
	return stats, nil
}

func supersedeVerdict(ep, sc string, v trace.Verdict, validFrom, now int64, evidence string) stmt {
	return stmt{`
		MATCH (e:Episode {id:$ep})
		MERGE (o:Objective {id:$oid}) ON CREATE SET o.name=$name, o.severity=$sev, o.asi=$asi, o.rec_from=$now
		WITH e, o
		OPTIONAL MATCH (e)-[cur:ASSESSED]->(o) WHERE cur.rec_to IS NULL
		WITH e, o, cur
		WHERE cur IS NULL OR cur.success <> $success OR cur.evidence <> $evidence
		FOREACH (_ IN CASE WHEN cur IS NULL THEN [] ELSE [1] END | SET cur.rec_to = $now)
		CREATE (e)-[n:ASSESSED {success:$success, evidence:$evidence, valid_from:$vf, valid_to:null, rec_from:$now, rec_to:null,
		        by:$by, reason:$reason, supersedes: CASE WHEN cur IS NULL THEN null ELSE elementId(cur) END}]->(o)`,
		map[string]any{"ep": ep, "oid": sc + "|" + v.ObjectiveID, "name": v.ObjectiveID, "sev": v.Severity, "asi": v.ASI,
			"success": v.Success, "evidence": evidence, "vf": validFrom, "now": now, "by": "oracle", "reason": "automatic verdict at ingest"}}
}

// Correct records a human (or improved-oracle) correction of an episode's verdict. Nothing is
// overwritten: the old belief is closed on the record axis and the new one points back at it, so
// "what did we believe last Tuesday" stays answerable. It returns false if nothing changed.
func (s *Store) Correct(ctx context.Context, ep, objective string, success bool, evidence, by, reason string) (bool, error) {
	rows, err := s.read(ctx, `MATCH (e:Episode {id:$ep}) RETURN e.scenario AS sc, e.start_ms AS vf`, map[string]any{"ep": ep})
	if err != nil {
		return false, err
	}
	if len(rows) == 0 {
		return false, fmt.Errorf("no such episode %s", ep)
	}
	sc, vf := asStr(rows[0]["sc"]), asInt(rows[0]["vf"])
	cur, err := s.read(ctx, `MATCH (e:Episode {id:$ep})-[a:ASSESSED]->(o:Objective {id:$oid}) WHERE a.rec_to IS NULL RETURN a.success AS success, a.evidence AS evidence`,
		map[string]any{"ep": ep, "oid": sc + "|" + objective})
	if err != nil {
		return false, err
	}
	if len(cur) == 0 {
		return false, fmt.Errorf("episode %s has no verdict for objective %q", ep, objective)
	}
	if cur[0]["success"] == success && asStr(cur[0]["evidence"]) == evidence {
		return false, nil
	}
	st := supersedeVerdict(ep, sc, trace.Verdict{ObjectiveID: objective, Success: success}, vf, time.Now().UnixMilli(), evidence)
	st.params["by"], st.params["reason"] = by, reason
	return true, s.write(ctx, []stmt{st})
}

func signerOf(tr *trace.Trace) any {
	if tr.Signature == nil {
		return nil
	}
	return tr.Signature.KeyID
}

func orStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

type vecItem struct {
	id      string
	text    string
	payload map[string]any
}

func (ix *Index) upsert(ctx context.Context, tr *trace.Trace, items []vecItem, scenarioName string) (int, error) {
	if err := ix.Q.EnsureCollection(ctx, ix.Collection, ix.Emb.Dim()); err != nil {
		return 0, err
	}
	texts := make([]string, len(items))
	for i, it := range items {
		texts[i] = it.text
	}
	vs, err := ix.Emb.Embed(ctx, texts)
	if err != nil {
		return 0, err
	}
	pts := make([]vec.Point, len(items))
	for i, it := range items {
		p := it.payload
		p["text"] = clip(it.text, 1200)
		p["scenario"], p["guard_mode"], p["target"], p["model"] = scenarioName, tr.GuardMode, tr.Target, tr.Model
		p["success"] = tr.Success
		if tr.Attack != nil {
			if _, ok := p["technique"]; !ok {
				p["technique"] = tr.Attack.Technique
			}
		}
		pts[i] = vec.Point{ID: it.id, Vector: vs[i], Payload: p}
	}
	return len(pts), ix.Q.Upsert(ctx, ix.Collection, pts)
}

// nullable stores an empty string as no property at all, so "has a fork_of" is a meaningful test in Cypher.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
