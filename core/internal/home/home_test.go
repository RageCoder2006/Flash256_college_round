package home

import (
	"os"
	"path/filepath"
	"testing"
)

func mkRoot(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	for _, s := range assetDirs {
		if err := os.MkdirAll(filepath.Join(d, s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestEnvOverridesAndResolve(t *testing.T) {
	root := mkRoot(t)
	if err := os.WriteFile(filepath.Join(root, "scenarios", "x.yaml"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AVHSOL_HOME", root)
	if Assets() != root {
		t.Fatalf("AVHSOL_HOME must win: %s", Assets())
	}
	other := t.TempDir()
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	_ = os.Chdir(other)
	if got := Resolve("scenarios/x.yaml"); got != filepath.Join(root, "scenarios", "x.yaml") {
		t.Fatalf("relative asset must resolve under AVHSOL_HOME from an unrelated directory: %s", got)
	}
	if got := Resolve("nope.yaml"); got != "nope.yaml" {
		t.Fatalf("unknown path must be unchanged: %s", got)
	}
	if got := Resolve("/abs/x"); got != "/abs/x" {
		t.Fatal("absolute unchanged")
	}
}

func TestStateAndConfigOverride(t *testing.T) {
	t.Setenv("AVHSOL_STATE", "/s")
	t.Setenv("AVHSOL_CONFIG", "/c")
	if StateDir() != "/s" || ConfigDir() != "/c" || SigningKey() != "/c/signing.key" || IntelDir() != "/s/intel" {
		t.Fatalf("%s %s %s %s", StateDir(), ConfigDir(), SigningKey(), IntelDir())
	}
}

func TestCheckoutFound(t *testing.T) {
	if Checkout() == "" {
		t.Skip("not running inside a checkout")
	}
	if Installed() {
		t.Fatal("a checkout is not an install")
	}
}

func TestSlug(t *testing.T) {
	if Slug("My Agent/v2") != "my-agent-v2" || Slug("///") != "agent" {
		t.Fatal(Slug("My Agent/v2"))
	}
}
