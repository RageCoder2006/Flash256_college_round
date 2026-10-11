package api

import (
	"encoding/json"
	"testing"
)

func TestNonNull(t *testing.T) {
	type inner struct{ Xs []int }
	type outer struct {
		A []string
		M map[string]int
		P *inner
		I any
		S []inner
		E *int
	}
	b, _ := json.Marshal(nonNull(outer{P: &inner{}, I: []int(nil), S: []inner{{}}}))
	want := `{"A":[],"M":{},"P":{"Xs":[]},"I":[],"S":[{"Xs":[]}],"E":null}`
	if string(b) != want {
		t.Fatalf("got %s\nwant %s", b, want)
	}
}
