package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/41vi4p/avhsol/core/internal/graph"
)

// Role is ordered: each role can do everything the roles below it can.
type Role int

const (
	RoleNone     Role = iota
	RoleViewer        // read reports, traces, graph
	RoleAnalyst       // + ask the graph, similar-search, correct verdicts
	RoleOperator      // + start runs, change the guard mode
	RoleAdmin         // + read the audit log
)

func (r Role) String() string {
	return [...]string{"none", "viewer", "analyst", "operator", "admin"}[r]
}

type token struct {
	role Role
	hash [32]byte // we keep only hashes in memory
	id   string   // short fingerprint for the audit log; never the token
}

// Auth checks bearer tokens. With Open set (development only) every caller is an admin.
type Auth struct {
	tokens []token
	Open   bool

	mu    sync.Mutex
	fails map[string][]time.Time
}

func hashTok(t string) [32]byte { return sha256.Sum256([]byte(t)) }

// LoadAuth reads AVHSOL_TOKEN_<ROLE> (or AVHSOL_TOKEN_<ROLE> from deploy/stack/.env).
func LoadAuth() *Auth {
	a := &Auth{fails: map[string][]time.Time{}}
	for _, r := range []Role{RoleViewer, RoleAnalyst, RoleOperator, RoleAdmin} {
		up := strings.ToUpper(r.String())
		if v := graph.Setting("AVHSOL_TOKEN_"+up, "AVHSOL_TOKEN_"+up, ""); v != "" {
			h := hashTok(v)
			a.tokens = append(a.tokens, token{role: r, hash: h, id: hex.EncodeToString(h[:3])})
		}
	}
	return a
}

func (a *Auth) Configured() bool { return len(a.tokens) > 0 }

// who identifies the caller for the audit log.
type who struct {
	Role Role
	ID   string
}

// Authenticate returns the caller's role. It compares against every token (no early exit) in
// constant time, so response time does not reveal which role or how much of a token matched.
func (a *Auth) Authenticate(r *http.Request) (who, bool) {
	if a.Open {
		return who{RoleAdmin, "open-dev"}, true
	}
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || tok == "" {
		return who{}, false
	}
	got := hashTok(tok)
	best := who{}
	for _, t := range a.tokens {
		if subtle.ConstantTimeCompare(got[:], t.hash[:]) == 1 && t.role > best.Role {
			best = who{t.role, t.id}
		}
	}
	return best, best.Role != RoleNone
}

// Throttled reports whether this client has failed too often recently (10 failures per minute).
func (a *Auth) Throttled(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	cut := time.Now().Add(-time.Minute)
	kept := a.fails[ip][:0]
	for _, t := range a.fails[ip] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	a.fails[ip] = kept
	return len(kept) >= 10
}

func (a *Auth) Fail(ip string) {
	a.mu.Lock()
	a.fails[ip] = append(a.fails[ip], time.Now())
	a.mu.Unlock()
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}
