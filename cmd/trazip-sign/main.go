// Command trazip-sign signs a release's update.json with the offline
// Ed25519 private key, producing update.json.sig. Release-pipeline-only:
// never built into TRAZIP.exe, never distributed to users, never run on a
// machine that doesn't already hold the private key in secure storage.
//
// Usage:
//
//	trazip-sign -key <path-to-private-key-hex-file> -manifest update.json -out update.json.sig
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	keyPath := flag.String("key", "", "path to a file containing the hex-encoded Ed25519 private key (64 bytes / 128 hex chars)")
	manifestPath := flag.String("manifest", "", "path to update.json to sign")
	outPath := flag.String("out", "", "path to write the hex-encoded signature to (e.g. update.json.sig)")
	flag.Parse()

	if *keyPath == "" || *manifestPath == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "usage: trazip-sign -key <private-key-file> -manifest update.json -out update.json.sig")
		os.Exit(2)
	}

	if err := run(*keyPath, *manifestPath, *outPath); err != nil {
		fmt.Fprintln(os.Stderr, "trazip-sign:", err)
		os.Exit(1)
	}
}

func run(keyPath, manifestPath, outPath string) error {
	keyHex, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("reading key file: %w", err)
	}
	keyBytes, err := hex.DecodeString(strings.TrimSpace(string(keyHex)))
	if err != nil {
		return fmt.Errorf("key file is not valid hex: %w", err)
	}
	if len(keyBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("private key is %d bytes, want %d (did you paste the public key by mistake?)", len(keyBytes), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(keyBytes)

	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("reading manifest: %w", err)
	}

	sig := ed25519.Sign(priv, manifest)
	sigHex := hex.EncodeToString(sig)

	if err := os.WriteFile(outPath, []byte(sigHex), 0o600); err != nil {
		return fmt.Errorf("writing signature: %w", err)
	}
	fmt.Println("Signed", manifestPath, "->", outPath)
	return nil
}
