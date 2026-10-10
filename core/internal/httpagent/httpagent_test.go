package httpagent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExtractPaths(t *testing.T) {
	b := []byte(`{"choices":[{"message":{"content":"hi"}}],"n":3}`)
	if Extract(b, "choices.0.message.content") != "hi" || Extract(b, "n") != "3" || Extract(b, "choices.5.x") != "" {
		t.Fatal("path extraction wrong")
	}
	if Extract([]byte("plain"), "") != "plain" || Extract([]byte("not json"), "a.b") != "not json" {
		t.Fatal("raw fallbacks wrong")
	}
}

func TestDriveSendsTemplatedBodyAndEnvHeaderAndReadsReply(t *testing.T) {
	t.Setenv("AG_TOKEN", "sekret")
	var got map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		_, _ = w.Write([]byte(`{"reply":"done"}`))
	}))
	defer srv.Close()
	s := &Spec{URL: srv.URL, Headers: map[string]string{"Authorization": "Bearer {env:AG_TOKEN}"}, ResponsePath: "reply", Body: `{"input": {task_json}, "k": 1}`}
	s.Defaults()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	r := s.Drive(context.Background(), `say "hi"`+"\n"+`now`)
	if r.Err != "" || r.Reply != "done" {
		t.Fatalf("%+v", r)
	}
	if got["input"] != "say \"hi\"\nnow" || auth != "Bearer sekret" {
		t.Fatalf("body/auth not rendered: %v %q", got, auth)
	}
}

func TestDriveReportsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", 401) }))
	defer srv.Close()
	s := &Spec{URL: srv.URL}
	s.Defaults()
	if r := s.Drive(context.Background(), "x"); !strings.Contains(r.Err, "401") {
		t.Fatalf("%+v", r)
	}
}

func TestContentServerServesOnlyListedDocsAndRecordsReads(t *testing.T) {
	cs, err := StartContentServer(map[string]string{"README.md": "poisoned"}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	r, _ := http.Get(cs.URL("README.md"))
	b, _ := io.ReadAll(r.Body)
	r2, _ := http.Get(cs.URL("secret.txt"))
	if string(b) != "poisoned" || r2.StatusCode != 404 {
		t.Fatal("served wrong content")
	}
	if f := cs.Fetches(); len(f) != 1 || f[0].Content != "poisoned" {
		t.Fatalf("reads not recorded: %+v", f)
	}
}

func TestMessagePlacement(t *testing.T) {
	s := &Spec{URL: "http://x", Placement: "inline"}
	s.Defaults()
	if m := s.Message("task", "http://u", "PAYLOAD"); m != "task\n\nPAYLOAD" {
		t.Fatalf("%q", m)
	}
	u := &Spec{URL: "http://x"}
	u.Defaults()
	if m := u.Message("task", "http://u/D", "PAYLOAD"); !strings.Contains(m, "http://u/D") || strings.Contains(m, "PAYLOAD") {
		t.Fatalf("%q", m)
	}
}
