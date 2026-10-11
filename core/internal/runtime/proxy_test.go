package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/41vi4p/avhsol/core/internal/home"
)

func TestHealthyAndExisting(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()
	p, err := EnsureProxy(context.Background(), Options{Existing: ts.URL + "/"})
	if err != nil || p.URL != ts.URL || p.Started {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := EnsureProxy(context.Background(), Options{Existing: "http://127.0.0.1:1"}); err == nil {
		t.Fatal("an unreachable existing proxy must be an error")
	}
}

func TestStartAndStopRealProxy(t *testing.T) {
	bin := home.Bin("avhsol-proxy")
	if _, err := exec.LookPath(bin); err != nil {
		t.Skip("avhsol-proxy not built")
	}
	p, err := EnsureProxy(context.Background(), Options{Upstream: "http://127.0.0.1:1/v1", Model: "m", APIKey: "dummy-not-a-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.URL, "http://127.0.0.1:") || !p.Started || !Healthy(context.Background(), p.URL) {
		t.Fatalf("%+v", p)
	}
	p.Stop()
	if Healthy(context.Background(), p.URL) {
		t.Fatal("proxy must be stopped")
	}
	_ = os.Stdout
}

func TestMissingBinary(t *testing.T) {
	if _, err := EnsureProxy(context.Background(), Options{Bin: "/nonexistent/avhsol-proxy"}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("%v", err)
	}
}
