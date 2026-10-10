// Package sign signs and verifies traces with Ed25519, so evidence handed to a security team can be
// shown to come from this platform and to be unmodified (a bare hash chain can be recomputed by anyone).
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/41vi4p/avhsol/core/internal/trace"
)

type Signer struct {
	priv ed25519.PrivateKey
	ID   string
}

// KeyID is a short fingerprint of the public key.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:6])
}

// Generate writes a new key pair: <path> (private, mode 0600) and <path>.pub.
func Generate(path string) (string, error) {
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("%s already exists; refusing to overwrite a signing key", path)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: priv.Seed()}), 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(path+".pub", pem.EncodeToMemory(&pem.Block{Type: "ED25519 PUBLIC KEY", Bytes: pub}), 0o644); err != nil {
		return "", err
	}
	return KeyID(pub), nil
}

func LoadSigner(path string) (*Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "ED25519 PRIVATE KEY" || len(blk.Bytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s is not an avhsol signing key", path)
	}
	priv := ed25519.NewKeyFromSeed(blk.Bytes)
	return &Signer{priv: priv, ID: KeyID(priv.Public().(ed25519.PublicKey))}, nil
}

func (s *Signer) Sign(tr *trace.Trace) {
	sig := ed25519.Sign(s.priv, tr.SigningMessage())
	tr.Signature = &trace.Signature{KeyID: s.ID, Sig: base64.StdEncoding.EncodeToString(sig)}
}

func LoadPublic(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "ED25519 PUBLIC KEY" || len(blk.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s is not an avhsol public key", path)
	}
	return ed25519.PublicKey(blk.Bytes), nil
}

// Verify checks the hash chain AND the signature. A trace without a signature fails.
func Verify(tr *trace.Trace, pub ed25519.PublicKey) error {
	if err := tr.Verify(); err != nil {
		return err
	}
	if tr.Signature == nil {
		return fmt.Errorf("trace %s is not signed", tr.TraceID)
	}
	if tr.Signature.KeyID != KeyID(pub) {
		return fmt.Errorf("trace %s was signed by key %s, not %s", tr.TraceID, tr.Signature.KeyID, KeyID(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(tr.Signature.Sig)
	if err != nil || !ed25519.Verify(pub, tr.SigningMessage(), sig) {
		return fmt.Errorf("trace %s: signature does not match its content", tr.TraceID)
	}
	return nil
}
