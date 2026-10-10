// Package redact removes secrets from text BEFORE it is written to the graph or the vector store.
// Known secrets (the scenario's canaries) are replaced by a stable fingerprint, so the graph can
// still say "this call leaked secret 3fa9c1…" without ever holding the secret itself.
package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var patterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"aws_key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`)},
	{"hf_token", regexp.MustCompile(`\bhf_[A-Za-z0-9]{12,}\b`)},
	{"slack_token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`)},
	{"api_key", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}\b`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)`)},
	{"ssn", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
}

// Fingerprint is a short, stable, non-reversible handle for a secret.
func Fingerprint(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:6])
}

// Text redacts known secrets first (so they keep a linkable fingerprint), then anything that
// looks like a credential. It returns the cleaned text and how many replacements were made.
func Text(s string, known []string) (string, int) {
	n := 0
	for _, k := range known {
		if k != "" && strings.Contains(s, k) {
			n += strings.Count(s, k)
			s = strings.ReplaceAll(s, k, "[SECRET:"+Fingerprint(k)+"]")
		}
	}
	for _, p := range patterns {
		s = p.re.ReplaceAllStringFunc(s, func(m string) string {
			n++
			return "[" + strings.ToUpper(p.name) + ":" + Fingerprint(m) + "]"
		})
	}
	return s, n
}
