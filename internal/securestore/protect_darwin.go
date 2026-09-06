//go:build darwin

package securestore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// macOS has no DPAPI, so the same contract (opaque per-user encryption with
// the key never touching disk in the data dir) is met with AES-256-GCM using
// a random key stored in the user's login Keychain via security(1). The
// Keychain entry is created on first Protect and reused afterwards, which
// mirrors DPAPI's "bound to this user on this machine" semantics.
const (
	keychainService = "TRAZIP"
	keychainAccount = "securestore-key"
	blobMagic       = "TZSS1" // versioned header so a future scheme can coexist
)

func Protect(plain []byte) ([]byte, error) {
	gcm, err := aead(true)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(blobMagic), nonce...)
	return gcm.Seal(out, nonce, plain, nil), nil
}

func Unprotect(cipherBlob []byte) ([]byte, error) {
	gcm, err := aead(false)
	if err != nil {
		return nil, err
	}
	rest, ok := strings.CutPrefix(string(cipherBlob), blobMagic)
	if !ok || len(rest) < gcm.NonceSize() {
		return nil, fmt.Errorf("blob de securestore inválido o de otra plataforma")
	}
	nonce, ct := []byte(rest[:gcm.NonceSize()]), []byte(rest[gcm.NonceSize():])
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("no se pudo descifrar (¿Keychain de otro usuario?): %w", err)
	}
	return plain, nil
}

func aead(createKey bool) (cipher.AEAD, error) {
	key, err := keychainKey(createKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// keychainKey fetches the store key from the login Keychain, generating and
// persisting a fresh 256-bit key on first use when create is allowed.
func keychainKey(create bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/security",
		"find-generic-password", "-s", keychainService, "-a", keychainAccount, "-w").Output()
	if err == nil {
		key, decErr := hex.DecodeString(strings.TrimSpace(string(out)))
		if decErr != nil || len(key) != 32 {
			return nil, fmt.Errorf("la clave de securestore en el Keychain está corrupta")
		}
		return key, nil
	}
	if !create {
		return nil, fmt.Errorf("no hay clave de securestore en el Keychain: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if out, err := exec.CommandContext(ctx, "/usr/bin/security",
		"add-generic-password", "-s", keychainService, "-a", keychainAccount,
		"-l", "TRAZIP securestore", "-w", hex.EncodeToString(key), "-U").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("no se pudo guardar la clave en el Keychain: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return key, nil
}
