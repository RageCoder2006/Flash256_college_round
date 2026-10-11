package graph

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/41vi4p/avhsol/core/internal/home"
	"github.com/41vi4p/avhsol/core/internal/vec"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Store is the Neo4j-backed trace graph.
type Store struct {
	drv neo4j.DriverWithContext
	db  string
}

// Config is read from the environment, falling back to deploy/stack/.env (written by scripts/stack.sh).
type Config struct{ URI, User, Password, Database string }

func dotenv() map[string]string {
	env := map[string]string{}
	for _, p := range []string{os.Getenv("AVHSOL_STACK_ENV"), filepath.Join(home.ConfigDir(), ".env"), filepath.Join(home.ConfigDir(), "stack.env"), "deploy/stack/.env", "../deploy/stack/.env", "../../deploy/stack/.env", "../../../deploy/stack/.env", "../../../../deploy/stack/.env"} {
		if p == "" {
			continue
		}
		if f, err := os.Open(p); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				if k, v, ok := strings.Cut(sc.Text(), "="); ok {
					env[strings.TrimSpace(k)] = strings.TrimSpace(v)
				}
			}
			f.Close()
			break
		}
	}
	return env
}

// Setting reads an environment variable, then a key from deploy/stack/.env, then a default.
func Setting(name, fileKey, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	if fileKey != "" {
		if v := dotenv()[fileKey]; v != "" {
			return v
		}
	}
	return def
}

func LoadConfig() Config {
	return Config{
		URI:      Setting("AVHSOL_NEO4J_URI", "", "bolt://127.0.0.1:7687"),
		User:     Setting("AVHSOL_NEO4J_USER", "", "neo4j"),
		Password: Setting("AVHSOL_NEO4J_PASSWORD", "NEO4J_PASSWORD", ""),
		Database: Setting("AVHSOL_NEO4J_DB", "", "neo4j"),
	}
}

// LoadIndex builds the vector index from settings: Qdrant plus an embedder (a real embedding
// endpoint if AVHSOL_EMBED_URL is set, otherwise the offline lexical embedder).
func LoadIndex() *Index {
	q := vec.NewQdrant(Setting("AVHSOL_QDRANT_URL", "", "http://127.0.0.1:6333"), Setting("AVHSOL_QDRANT_API_KEY", "QDRANT_API_KEY", ""))
	var emb vec.Embedder = vec.NewHashEmbedder()
	if u := os.Getenv("AVHSOL_EMBED_URL"); u != "" {
		emb = vec.NewHTTPEmbedder(u, os.Getenv("AVHSOL_EMBED_MODEL"), os.Getenv("AVHSOL_EMBED_API_KEY"))
	}
	return &Index{Q: q, Emb: emb, Collection: "avhsol_" + strings.NewReplacer("-", "_", ":", "_", ".", "_", "/", "_").Replace(emb.Name())}
}

func Open(ctx context.Context, c Config) (*Store, error) {
	if c.Password == "" {
		return nil, fmt.Errorf("no Neo4j password: run scripts/stack.sh up, or set AVHSOL_NEO4J_PASSWORD")
	}
	drv, err := neo4j.NewDriverWithContext(c.URI, neo4j.BasicAuth(c.User, c.Password, ""))
	if err != nil {
		return nil, err
	}
	vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := drv.VerifyConnectivity(vctx); err != nil {
		_ = drv.Close(ctx)
		return nil, fmt.Errorf("neo4j at %s: %w (is the stack up? scripts/stack.sh up)", c.URI, err)
	}
	return &Store{drv: drv, db: c.Database}, nil
}

func (s *Store) Close(ctx context.Context) { _ = s.drv.Close(ctx) }

// Rows are query results as plain maps.
type Rows []map[string]any

func (s *Store) read(ctx context.Context, cypher string, params map[string]any) (Rows, error) {
	sess := s.drv.NewSession(ctx, neo4j.SessionConfig{DatabaseName: s.db, AccessMode: neo4j.AccessModeRead})
	defer sess.Close(ctx)
	res, err := sess.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}
		return collect(ctx, r)
	})
	if err != nil {
		return nil, err
	}
	return res.(Rows), nil
}

func collect(ctx context.Context, r neo4j.ResultWithContext) (Rows, error) {
	var out Rows
	for r.Next(ctx) {
		rec := r.Record()
		row := map[string]any{}
		for i, k := range rec.Keys {
			row[k] = rec.Values[i]
		}
		out = append(out, row)
	}
	return out, r.Err()
}

// write runs several statements in one transaction.
func (s *Store) write(ctx context.Context, stmts []stmt) error {
	sess := s.drv.NewSession(ctx, neo4j.SessionConfig{DatabaseName: s.db, AccessMode: neo4j.AccessModeWrite})
	defer sess.Close(ctx)
	_, err := sess.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		for _, st := range stmts {
			r, err := tx.Run(ctx, st.cypher, st.params)
			if err != nil {
				return nil, fmt.Errorf("%w\n  in: %.160s", err, strings.Join(strings.Fields(st.cypher), " "))
			}
			if _, err := r.Consume(ctx); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	return err
}

type stmt struct {
	cypher string
	params map[string]any
}

// EnsureSchema creates uniqueness constraints and lookup indexes (idempotent).
func (s *Store) EnsureSchema(ctx context.Context) error {
	var st []stmt
	for _, l := range []string{"Episode", "Step", "Agent", "Tool", "Resource", "Payload", "Technique", "Objective", "Defense", "Secret", "Finding", "Intel"} {
		st = append(st, stmt{fmt.Sprintf("CREATE CONSTRAINT %s_id IF NOT EXISTS FOR (n:%s) REQUIRE n.id IS UNIQUE", strings.ToLower(l), l), nil})
	}
	st = append(st,
		stmt{"CREATE INDEX step_ep IF NOT EXISTS FOR (n:Step) ON (n.ep, n.seq)", nil},
		stmt{"CREATE INDEX episode_time IF NOT EXISTS FOR (n:Episode) ON (n.start_ms)", nil},
		stmt{"CREATE INDEX assessed_rec IF NOT EXISTS FOR ()-[r:ASSESSED]-() ON (r.rec_to)", nil},
	)
	return s.write(ctx, st)
}

// Stats counts what the graph holds.
func (s *Store) Stats(ctx context.Context) (Rows, error) {
	return s.read(ctx, `
		CALL { MATCH (n) UNWIND labels(n) AS l RETURN l AS label, count(*) AS n }
		RETURN label, n ORDER BY n DESC`, nil)
}

// Relink connects guarded replays to the unguarded episodes they replay, and records which defenses
// stopped them. It is a separate idempotent pass (not part of IngestTrace) because a replay can be
// ingested before its baseline; run it after a batch of ingests.
func (s *Store) Relink(ctx context.Context) error {
	return s.write(ctx, []stmt{
		{`MATCH (e:Episode {kind:'attack'})-[:PLANTED]->(p:Payload)-[:PLANTED_IN]->(res:Resource)
		  WHERE e.guard_mode <> 'off'
		  MATCH (o:Episode {scenario:e.scenario, guard_mode:'off'})-[:PLANTED]->(p)
		  WHERE o.id <> e.id AND o.target = e.target
		  MERGE (e)-[:REPLAY_OF]->(o)`, nil},
		{`MATCH (e:Episode) WHERE e.fork_of IS NOT NULL
		  MATCH (o:Episode {id:e.fork_of})
		  MERGE (e)-[r:FORKED_FROM]->(o) SET r.at=e.fork_at`, nil},
		{`MATCH (e:Episode)-[:HAS_STEP]->(g:GuardDecision)-[:BY_RULE]->(d:Defense)
		  WHERE e.guard_mode = 'enforce' AND g.decision <> 'allow'
		  MERGE (d)-[:STOPPED]->(e)`, nil},
	})
}

// Reset deletes EVERYTHING in the graph database. Callers must have confirmed with the user.
func (s *Store) Reset(ctx context.Context) error {
	for {
		rows, err := s.read(ctx, "MATCH (n) RETURN count(n) AS n", nil)
		if err != nil {
			return err
		}
		if asInt(rows[0]["n"]) == 0 {
			return nil
		}
		if err := s.write(ctx, []stmt{{"MATCH (n) WITH n LIMIT 5000 DETACH DELETE n", nil}}); err != nil {
			return err
		}
	}
}
