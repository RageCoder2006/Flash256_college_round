package redact

import (
	"strings"
	"testing"
)

func TestKnownSecretsKeepAStableFingerprint(t *testing.T) {
	a, n := Text("token=hf_canaryX9f2k7q1m4 and again hf_canaryX9f2k7q1m4", []string{"hf_canaryX9f2k7q1m4"})
	if strings.Contains(a, "canaryX9") || n != 2 {
		t.Fatalf("secret leaked or miscounted: %q n=%d", a, n)
	}
	b, _ := Text("x hf_canaryX9f2k7q1m4", []string{"hf_canaryX9f2k7q1m4"})
	fp := "[SECRET:" + Fingerprint("hf_canaryX9f2k7q1m4") + "]"
	if !strings.Contains(a, fp) || !strings.Contains(b, fp) {
		t.Fatalf("fingerprint must be stable across texts: %q %q", a, b)
	}
}

func TestPatternRedactionCatchesUnknownCredentials(t *testing.T) {
	in := "AKIAIOSFODNN7EXAMPLE ghp_abcdefghijklmnopqrstuvwxyz0123 sk-live_abcdefghijklmnop 123-45-6789"
	out, n := Text(in, nil)
	for _, bad := range []string{"AKIAIOSFODNN7EXAMPLE", "ghp_abcdef", "sk-live_abc", "123-45-6789"} {
		if strings.Contains(out, bad) {
			t.Fatalf("%s survived: %s", bad, out)
		}
	}
	if n != 4 {
		t.Fatalf("n=%d out=%s", n, out)
	}
}

func TestPlainTextIsUntouched(t *testing.T) {
	if out, n := Text("send the report to manager@corp.example", nil); out != "send the report to manager@corp.example" || n != 0 {
		t.Fatalf("%q %d", out, n)
	}
}
