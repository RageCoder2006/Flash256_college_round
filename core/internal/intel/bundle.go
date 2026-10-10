package intel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/41vi4p/avhsol/core/internal/sign"
)

const bundleFormat = "avhsol-intel-bundle/1"
const bundleDomain = "avhsol-intel-bundle"

// Bundle is the file that carries intel into a network-isolated deployment.
type Bundle struct {
	Format    string `json:"format"`
	Created   string `json:"created"`
	Items     []Item `json:"items"`
	SHA256    string `json:"sha256"`              // of the canonical items JSON
	KeyID     string `json:"key_id,omitempty"`    // who signed
	Signature string `json:"signature,omitempty"` // over the digest
}

func canonicalItems(items []Item) []byte {
	sort.Slice(items, func(i, j int) bool { return items[i].Key() < items[j].Key() })
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(items)
	return buf.Bytes()
}

// ExportBundle writes every cached item to path, signed when a signer is given.
func ExportBundle(s *Store, signer *sign.Signer, path string) (*Bundle, error) {
	items := s.Query(Filter{})
	b := &Bundle{Format: bundleFormat, Created: time.Now().UTC().Format(time.RFC3339), Items: items}
	sum := sha256.Sum256(canonicalItems(b.Items))
	b.SHA256 = hex.EncodeToString(sum[:])
	if signer != nil {
		b.KeyID, b.Signature = signer.SignBytes(bundleDomain, []byte(b.SHA256))
	}
	out, _ := json.MarshalIndent(b, "", " ")
	return b, os.WriteFile(path, out, 0o644)
}

// ImportBundle verifies a bundle and merges it into the store. Without a public key it refuses unless
// allowUnsigned is set, because intel steers what the platform attacks and reports.
func ImportBundle(s *Store, path string, pub ed25519.PublicKey, allowUnsigned bool) (added, updated int, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	var b Bundle
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return 0, 0, fmt.Errorf("not an intel bundle: %w", err)
	}
	if b.Format != bundleFormat {
		return 0, 0, fmt.Errorf("unsupported bundle format %q", b.Format)
	}
	sum := sha256.Sum256(canonicalItems(append([]Item(nil), b.Items...)))
	if hex.EncodeToString(sum[:]) != b.SHA256 {
		return 0, 0, fmt.Errorf("bundle digest does not match its contents")
	}
	switch {
	case pub != nil && b.Signature != "":
		if !sign.VerifyBytes(pub, bundleDomain, []byte(b.SHA256), b.Signature) {
			return 0, 0, fmt.Errorf("bundle signature is not valid for the configured key")
		}
	case pub != nil:
		return 0, 0, fmt.Errorf("bundle is unsigned but a verification key is configured")
	case !allowUnsigned:
		return 0, 0, fmt.Errorf("bundle cannot be verified: configure the signing public key or pass -allow-unsigned")
	}
	added, updated = s.Upsert(b.Items)
	return added, updated, nil
}
