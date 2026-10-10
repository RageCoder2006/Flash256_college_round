package cliagent

import "testing"

func TestExpand(t *testing.T) {
	t.Setenv("AB_TEST_VAR", "hello")
	got := Expand("run {task} in {workspace} with {env:AB_TEST_VAR} and {unknown}", Vars{"task": "T", "workspace": "/w"})
	if got != "run T in /w with hello and {unknown}" {
		t.Fatal(got)
	}
}

func TestCanonicalToolNames(t *testing.T) {
	tg := &Target{ToolAliases: map[string]string{"Execute": "bash", "ReadFile": "read"}}
	cases := map[string]string{"Bash": "bash", "shell": "bash", "Execute": "bash", "ReadFile": "read", "Read": "read", "local_shell": "bash"}
	for in, want := range cases {
		if got := tg.Canonical(in); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}
