package campaign

import "testing"

func TestRecordedWorkspacePathsAreRebasedToTheNewWorkspace(t *testing.T) {
	got := rebaseWorkspace(map[string]any{"path": "/tmp/avhsol-ep-799711612/workspace/README.md", "n": 3.0}, "/tmp/avhsol-ep-1/workspace")
	if got["path"] != "/tmp/avhsol-ep-1/workspace/README.md" || got["n"] != 3.0 {
		t.Fatalf("%v", got)
	}
	if rebaseText("cd /tmp/avhsol-ep-9/workspace && ls", "/w") != "cd /w && ls" {
		t.Fatal("text not rebased")
	}
	if rebaseWorkspace(nil, "/w") != nil {
		t.Fatal("nil args must stay nil")
	}
}
