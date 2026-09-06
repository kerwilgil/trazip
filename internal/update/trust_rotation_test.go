package update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// newTrustAnchorHex is the v1.4.0+ update-manifest verification key, as
// documented in sign.go. The matching private key is held offline, so these
// tests cannot produce a signature that verifies against the real anchor;
// productive-path assertions below swap in a synthetic key via publicKey,
// exactly the way internal/update/sign_test.go does.
const newTrustAnchorHex = "a94f501667c8de95e7c056a1d6493f61cf10d6849e155f32837fcf543a9cc149"

// oldTrustAnchorHex is the v1.3.2-and-earlier PUBLIC key (see sign.go). It is
// a public key only: no private key or seed for it exists in this repo, and it
// must never be fed to ed25519.NewKeyFromSeed as a signing seed.
const oldTrustAnchorHex = "ec8c7353f673a9d0b5a43e91a0c062f9444e6416b09cb51d1220805be6aedd16"

// TestTrustRotationTrustAnchor pins the embedded trust anchor: both the hex
// constant in sign.go and the parsed bytes of publicKey must be exactly the
// rotated v1.4.0 key.
func TestTrustRotationTrustAnchor(t *testing.T) {
	if publicKeyHex != newTrustAnchorHex {
		t.Fatalf("embedded publicKeyHex = %q, want rotated v1.4.0 trust anchor %q", publicKeyHex, newTrustAnchorHex)
	}

	want, err := hex.DecodeString(newTrustAnchorHex)
	if err != nil {
		t.Fatalf("newTrustAnchorHex is not valid hex: %v", err)
	}
	if len(want) != ed25519.PublicKeySize {
		t.Fatalf("trust anchor is %d bytes, want %d", len(want), ed25519.PublicKeySize)
	}
	if !bytes.Equal(publicKey, want) {
		t.Fatalf("parsed publicKey does not contain the trust anchor bytes:\n got %x\nwant %x", publicKey, want)
	}
}

// TestTrustRotationNewKey exercises the productive path (verifyManifest) with a
// synthetic keypair swapped in for the embedded key: a genuine signature from
// the trusted key is accepted, one from any other key is rejected.
func TestTrustRotationNewKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	orig := publicKey
	publicKey = pub
	defer func() { publicKey = orig }()

	manifest := []byte(`{"version":"1.4.0-test"}`)
	sig := ed25519.Sign(priv, manifest)

	// Positive control: a genuine signature from the trusted key verifies.
	if err := verifyManifest(manifest, hex.EncodeToString(sig)); err != nil {
		t.Fatalf("verifyManifest rejected a genuine signature from the trusted key: %v", err)
	}

	// Negative control: a signature from an untrusted key does not.
	_, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherSig := ed25519.Sign(otherPriv, manifest)
	if err := verifyManifest(manifest, hex.EncodeToString(otherSig)); err == nil {
		t.Fatal("verifyManifest accepted a signature from an untrusted key - must reject")
	}
}

// TestTrustRotationOldKeyRejected covers the trust-generation transition.
//
// Limitation: this repo has no historical v1.3.2 fixture (update.json +
// update.json.sig) and no private key for the old anchor, so this test cannot
// replay a real historical signature. It asserts what it can on the productive
// path: the rotation actually changed the key, the embedded key is the new
// anchor, and verifyManifest() rejects a signature that was not produced by the
// currently trusted private key (wrong-key rejection).
func TestTrustRotationOldKeyRejected(t *testing.T) {
	oldPub, err := hex.DecodeString(oldTrustAnchorHex)
	if err != nil {
		t.Fatalf("oldTrustAnchorHex is not valid hex: %v", err)
	}
	newPub, err := hex.DecodeString(newTrustAnchorHex)
	if err != nil {
		t.Fatalf("newTrustAnchorHex is not valid hex: %v", err)
	}

	if bytes.Equal(oldPub, newPub) {
		t.Fatal("old and new trust anchors are identical - no rotation happened")
	}
	if !bytes.Equal(publicKey, newPub) {
		t.Fatal("embedded publicKey is not the new trust anchor")
	}

	// Wrong-key rejection against the real production anchor (publicKey is left
	// untouched here). A signature from any key other than the offline v1.4.0
	// private key must fail.
	_, wrongPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"version":"1.3.2"}`)
	wrongSig := ed25519.Sign(wrongPriv, manifest)
	if err := verifyManifest(manifest, hex.EncodeToString(wrongSig)); err == nil {
		t.Fatal("verifyManifest accepted a non-trusted signature against the production anchor - must reject")
	}
}

// TestTrustRotationNoFallback verifies there is no fallback to a second key and
// no silent bypass: only a signature from the single embedded key verifies.
func TestTrustRotationNoFallback(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	orig := publicKey
	publicKey = pub
	defer func() { publicKey = orig }()

	manifest := []byte(`{"version":"1.4.0-test"}`)

	// Positive control.
	goodSig := ed25519.Sign(priv, manifest)
	if err := verifyManifest(manifest, hex.EncodeToString(goodSig)); err != nil {
		t.Fatalf("positive control failed: genuine signature rejected: %v", err)
	}

	// A second, unrelated keypair stands in for "the old key" or any other key.
	// There is no fallback path that would accept it.
	_, oldLikePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldLikeSig := ed25519.Sign(oldLikePriv, manifest)
	if err := verifyManifest(manifest, hex.EncodeToString(oldLikeSig)); err == nil {
		t.Fatal("a signature from a non-embedded key verified - fallback detected")
	}

	// An empty or all-zero signature must not be a silent bypass either.
	if err := verifyManifest(manifest, ""); err == nil {
		t.Fatal("empty signature accepted - must reject")
	}
	zero := make([]byte, ed25519.SignatureSize)
	if err := verifyManifest(manifest, hex.EncodeToString(zero)); err == nil {
		t.Fatal("all-zero signature accepted - must reject")
	}
}

// TestTrustRotationTamperedManifest rejects a manifest altered after signing.
// The positive control runs first so the negative check cannot pass merely
// because the signature was never valid.
func TestTrustRotationTamperedManifest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	orig := publicKey
	publicKey = pub
	defer func() { publicKey = orig }()

	manifest := []byte(`{"version":"1.4.0-test"}`)
	sig := ed25519.Sign(priv, manifest)

	if err := verifyManifest(manifest, hex.EncodeToString(sig)); err != nil {
		t.Fatalf("positive control failed: genuine signature rejected: %v", err)
	}

	tampered := make([]byte, len(manifest))
	copy(tampered, manifest)
	tampered[0] ^= 0x01
	if err := verifyManifest(tampered, hex.EncodeToString(sig)); err == nil {
		t.Fatal("verifyManifest accepted a tampered manifest - must reject")
	}
}

// TestTrustRotationTamperedSignature rejects a signature altered after signing.
// The positive control runs first for the same reason as above.
func TestTrustRotationTamperedSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	orig := publicKey
	publicKey = pub
	defer func() { publicKey = orig }()

	manifest := []byte(`{"version":"1.4.0-test"}`)
	sig := ed25519.Sign(priv, manifest)

	if err := verifyManifest(manifest, hex.EncodeToString(sig)); err != nil {
		t.Fatalf("positive control failed: genuine signature rejected: %v", err)
	}

	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[len(tampered)-1] ^= 0x01
	if err := verifyManifest(manifest, hex.EncodeToString(tampered)); err == nil {
		t.Fatal("verifyManifest accepted a tampered signature - must reject")
	}
}
