package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryIsConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, tl := range All() {
		if !strings.HasPrefix(tl.Name, "avhsol_") || seen[tl.Name] {
			t.Errorf("bad or duplicate name %q", tl.Name)
		}
		seen[tl.Name] = true
		if tl.Handler == nil || tl.Title == "" || tl.Description == "" || tl.Schema["type"] != "object" {
			t.Errorf("%s is incomplete", tl.Name)
		}
		if tl.MinRole < Viewer || tl.MinRole > Admin {
			t.Errorf("%s role %d", tl.Name, tl.MinRole)
		}
		if tl.Effect == EffectLaunches && (DefaultExposed(tl) || tl.MinRole < Operator) {
			t.Errorf("%s launches agents: off by default and operator-only", tl.Name)
		}
		if tl.Effect == EffectWrites && tl.MinRole < Analyst {
			t.Errorf("%s writes: not for viewers", tl.Name)
		}
	}
	if _, ok := Find("avhsol_scan_codebase"); !ok {
		t.Fatal("Find")
	}
}

func TestRunsAreOnlyOpenedFromKnownDirectories(t *testing.T) {
	state := t.TempDir()
	t.Setenv("AVHSOL_STATE", state)
	run := filepath.Join(state, "runs", "demo-1", "dyn", "traces")
	if err := os.MkdirAll(run, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(run, "tr-x.json"), []byte(`{"trace_id":"tr-x"}`), 0o600)
	env := Env{}
	tl, _ := Find("avhsol_list_traces")
	if _, err := Call(context.Background(), env, tl, json.RawMessage(`{"run":"../../etc"}`)); err == nil {
		t.Fatal("a path is not a run name")
	}
	if _, err := Call(context.Background(), env, tl, json.RawMessage(`{"run":"demo-1"}`)); err != nil {
		t.Fatalf("known run: %v", err)
	}
	gt, _ := Find("avhsol_get_trace")
	if _, err := Call(context.Background(), env, gt, json.RawMessage(`{"id":"../tr-x","run":"demo-1"}`)); err == nil {
		t.Fatal("a trace id with a slash must be refused")
	}
}

func TestCallRejectsNonObjectArguments(t *testing.T) {
	tl, _ := Find("avhsol_status")
	if _, err := Call(context.Background(), Env{}, tl, json.RawMessage(`[1]`)); err == nil {
		t.Fatal("arguments must be an object")
	}
	if _, err := Call(context.Background(), Env{}, tl, nil); err != nil {
		t.Fatalf("no arguments is fine: %v", err)
	}
}
