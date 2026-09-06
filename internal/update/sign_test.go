package update

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestVerifyManifestAcceptsGenuineSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"version":"0.7.4"}`)
	sig := ed25519.Sign(priv, msg)

	// Swap in a test key so this doesn't depend on (or need to know) the
	// real embedded production key.
	orig := publicKey
	publicKey = pub
	defer func() { publicKey = orig }()

	if err := verifyManifest(msg, hex.EncodeToString(sig)); err != nil {
		t.Errorf("verifyManifest with a genuine signature failed: %v", err)
	}
}

func TestVerifyManifestRejectsTamperedContent(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"version":"0.7.4"}`)
	sig := ed25519.Sign(priv, msg)

	orig := publicKey
	publicKey = pub
	defer func() { publicKey = orig }()

	tampered := []byte(`{"version":"9.9.9"}`)
	if err := verifyManifest(tampered, hex.EncodeToString(sig)); err == nil {
		t.Error("verifyManifest accepted a signature over different content — must reject")
	}
}

func TestVerifyManifestRejectsWrongKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"version":"0.7.4"}`)
	sig := ed25519.Sign(priv, msg) // signed with priv, but publicKey below is otherPub

	orig := publicKey
	publicKey = otherPub
	defer func() { publicKey = orig }()

	if err := verifyManifest(msg, hex.EncodeToString(sig)); err == nil {
		t.Error("verifyManifest accepted a signature from the wrong keypair — must reject")
	}
}

func TestVerifyManifestRejectsMalformedSignature(t *testing.T) {
	if err := verifyManifest([]byte("x"), "not-hex-at-all"); err == nil {
		t.Error("expected an error for non-hex signature")
	}
	if err := verifyManifest([]byte("x"), "aabb"); err == nil {
		t.Error("expected an error for a too-short signature")
	}
}

func TestEmbeddedPublicKeyParsesToCorrectSize(t *testing.T) {
	raw, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("embedded public key is not valid hex: %v", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		t.Errorf("embedded public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
}
