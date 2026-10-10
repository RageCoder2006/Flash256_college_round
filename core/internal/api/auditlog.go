package api

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditLog is an append-only JSONL file in which every line commits to the one before it, so removing
// or editing a line is detectable (avhsol auditlog verify). It records who did what, never secrets.
type AuditLog struct {
	mu   sync.Mutex
	f    *os.File
	prev string
}

type AuditEntry struct {
	TS     int64  `json:"ts"`
	Who    string `json:"who"`
	Role   string `json:"role"`
	Remote string `json:"remote"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	Note   string `json:"note,omitempty"`
	Prev   string `json:"prev"`
	Hash   string `json:"hash"`
}

func entryHash(e AuditEntry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func OpenAuditLog(path string) (*AuditLog, error) {
	prev := ""
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var e AuditEntry
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				prev = e.Hash
			}
		}
		f.Close()
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &AuditLog{f: f, prev: prev}, nil
}

func (l *AuditLog) Write(e AuditEntry) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e.TS, e.Prev = time.Now().UnixMilli(), l.prev
	e.Hash = entryHash(e)
	b, _ := json.Marshal(e)
	_, _ = l.f.Write(append(b, '\n'))
	_ = l.f.Sync()
	l.prev = e.Hash
}

// VerifyAuditLog checks the chain and returns the number of entries.
func VerifyAuditLog(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	prev, n := "", 0
	for sc.Scan() {
		var e AuditEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return n, fmt.Errorf("line %d: unreadable: %w", n+1, err)
		}
		if e.Prev != prev || e.Hash != entryHash(e) {
			return n, fmt.Errorf("audit log broken at entry %d (an entry was changed, removed or inserted)", n+1)
		}
		prev, n = e.Hash, n+1
	}
	return n, sc.Err()
}

// Tail returns the last n entries.
func TailAuditLog(path string, n int) ([]AuditEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var all []AuditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			all = append(all, e)
		}
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all, sc.Err()
}
