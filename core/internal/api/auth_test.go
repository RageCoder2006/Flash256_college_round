package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditLogDetectsEditsAndRemovals(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := OpenAuditLog(p)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		l.Write(AuditEntry{Who: "x", Role: "analyst", Method: "POST", Path: "/api/graph/correct", Status: 200})
	}
	if n, err := VerifyAuditLog(p); err != nil || n != 4 {
		t.Fatalf("clean log: n=%d err=%v", n, err)
	}
	raw, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	// remove the second entry
	os.WriteFile(p, []byte(lines[0]+"\n"+lines[2]+"\n"+lines[3]+"\n"), 0o600)
	if _, err := VerifyAuditLog(p); err == nil {
		t.Fatal("removing an entry must be detected")
	}
	// edit an entry
	os.WriteFile(p, []byte(strings.Replace(string(raw), "analyst", "admin", 1)), 0o600)
	if _, err := VerifyAuditLog(p); err == nil {
		t.Fatal("editing an entry must be detected")
	}
}

func TestAuditLogChainSurvivesReopen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := OpenAuditLog(p)
	l.Write(AuditEntry{Who: "a"})
	l2, _ := OpenAuditLog(p)
	l2.Write(AuditEntry{Who: "b"})
	if n, err := VerifyAuditLog(p); err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}
