package cliagent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// Runs a real container: skipped unless docker with runsc is available and ../../bin/avhsol exists.
func TestGVisorConfinesTheAgentButReachesTheAllowedPort(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	if err := GVisorAvailable(context.Background()); err != nil {
		t.Skip(err)
	}
	self, err := filepath.Abs("../../bin/avhsol")
	if _, serr := os.Stat(self); err != nil || serr != nil {
		t.Skip("build core/bin/avhsol first")
	}
	var hits atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer sink.Close()
	u, _ := url.Parse(sink.URL)
	secretDir := t.TempDir()
	secret := filepath.Join(secretDir, "host-secret.txt")
	_ = os.WriteFile(secret, []byte("TOP-SECRET"), 0o600)
	ws := t.TempDir()
	_ = os.Chmod(ws, 0o755)

	script := `
exec 3<>/dev/tcp/127.0.0.1/` + u.Port() + ` && printf 'GET /hit HTTP/1.0\r\n\r\n' >&3 && echo allowed-port-ok
(exec 4<>/dev/tcp/1.1.1.1/80) 2>/dev/null && echo INTERNET-REACHABLE || echo internet-blocked
cat ` + secret + ` 2>/dev/null && echo HOST-SECRET-READ || echo host-secret-unreachable
echo "marker" > ` + filepath.Join(ws, "written.txt") + ` && echo workspace-writable
touch /usr/x 2>/dev/null && echo USR-WRITABLE || echo usr-readonly
`
	tg := &Target{Name: "probe", Kind: "cli", Isolation: IsolationGVisor, GVisor: GVisorConfig{SelfBin: self}, TimeoutSec: 120, Command: []string{"bash", "-c", script}, Env: map[string]string{"PATH": "/usr/bin:/bin"}}
	res := tg.Run(context.Background(), "", ws, []int{atoi(u.Port())}, Vars{})
	if res.Err != "" {
		t.Fatalf("run: %s\n%s", res.Err, res.Stdout)
	}
	for _, want := range []string{"allowed-port-ok", "internet-blocked", "host-secret-unreachable", "workspace-writable", "usr-readonly"} {
		if !strings.Contains(res.Stdout, want) {
			t.Errorf("missing %q in output:\n%s", want, res.Stdout)
		}
	}
	for _, bad := range []string{"INTERNET-REACHABLE", "HOST-SECRET-READ", "USR-WRITABLE"} {
		if strings.Contains(res.Stdout, bad) {
			t.Errorf("isolation failed: %s\n%s", bad, res.Stdout)
		}
	}
	if hits.Load() < 1 {
		t.Errorf("the forwarded port should have been hit, got %d", hits.Load())
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
