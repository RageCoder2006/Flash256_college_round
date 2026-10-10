// Package graph stores everything an agent did as a bitemporal property graph in Neo4j.
//
// Two clocks, as in utopia's design (docs/design/time.md), and every read says which:
//
//	world axis:  valid_from / valid_to      when something held or happened in the world
//	record axis: rec_from   / rec_to        when AVHSOL held it to be true
//
// A correction never overwrites: it closes the old row (rec_to = now) and creates a new one that
// points at it (supersedes). Reads take `at` (world) and `asOf` (record) separately; at absent
// means every moment, asOf absent means "what we believe now".
//
// The two predicates below are the ONLY place either axis is spelled. Query code must call them;
// a hand-written `rec_to IS NULL` elsewhere is a bug (it is how history queries quietly go wrong).
package graph

import "fmt"

// Kind is how a fact sits on the world axis.
type Kind int

const (
	// State holds over an interval [valid_from, valid_to): a permission, a memory entry, a policy.
	State Kind = iota
	// Event happened at one moment: a tool call, a guard decision. It is part of the world from then on.
	Event
)

// Clock selects a point on each axis. nil means "no constraint" (world) / "now" (record).
type Clock struct {
	At   *int64 // world time, epoch ms
	AsOf *int64 // record time, epoch ms
}

// Where returns a Cypher boolean expression and its parameters for relationship/node alias `a`.
// Parameter names are prefixed with the alias so several aliases can be combined in one query.
func (c Clock) Where(a string, k Kind) (string, map[string]any) {
	params := map[string]any{}
	record := fmt.Sprintf("%s.rec_to IS NULL", a)
	if c.AsOf != nil {
		record = fmt.Sprintf("(%s.rec_from <= $%s_asof AND (%s.rec_to IS NULL OR %s.rec_to > $%s_asof))", a, a, a, a, a)
		params[a+"_asof"] = *c.AsOf
	}
	world := "true"
	if c.At != nil {
		switch k {
		case Event:
			world = fmt.Sprintf("%s.valid_from <= $%s_at", a, a)
		default:
			world = fmt.Sprintf("(%s.valid_from <= $%s_at AND (%s.valid_to IS NULL OR %s.valid_to > $%s_at))", a, a, a, a, a)
		}
		params[a+"_at"] = *c.At
	}
	return record + " AND " + world, params
}

func merge(dst map[string]any, src map[string]any) {
	for k, v := range src {
		dst[k] = v
	}
}
