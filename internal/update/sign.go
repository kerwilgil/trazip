package update

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

// publicKeyHex is TRAZIP's update-manifest verification key.
// v1.3.2 and earlier used: ec8c7353f673a9d0b5a43e91a0c062f9444e6416b09cb51d1220805be6aedd16
// v1.4.0+ uses this key (rotated due to loss of original private key).
// The matching private key is held offline, outside any repository.
// Trust generation transition: v1.3.2 and earlier trust OLD key.
// v1.4.0+ trusts NEW key (same repository, new trust generation).
// This is a trust-generation transition; no channel migration.
const publicKeyHex = "a94f501667c8de95e7c056a1d6493f61cf10d6849e155f32837fcf543a9cc149"

// publicKey parses publicKeyHex once. A malformed constant is a programmer
// error caught immediately (init panics) rather than a silent
// always-fails-verification bug discovered later from a support report.
var publicKey = mustParsePublicKey(publicKeyHex)

func mustParsePublicKey(hexKey string) ed25519.PublicKey {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		panic("update: invalid embedded public key hex: " + err.Error())
	}
	if len(raw) != ed25519.PublicKeySize {
		panic(fmt.Sprintf("update: embedded public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize))
	}
	return ed25519.PublicKey(raw)
}

// verifyManifest checks manifestBytes against sigHex using the embedded
// public key. Nothing in this package trusts a Manifest's contents —
// version, asset URL, or SHA-256 — until this returns true. sigHex is the
// raw signature bytes, hex-encoded (update.json.sig's contents).
func verifyManifest(manifestBytes []byte, sigHex string) error {
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("signature is not valid hex: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(publicKey, manifestBytes, sig) {
		return fmt.Errorf("manifest signature verification failed")
	}
	return nil
}
