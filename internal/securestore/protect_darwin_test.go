//go:build darwin

package securestore

import (
	"bytes"
	"testing"
)

func TestProtectUnprotectRoundTrip(t *testing.T) {
	plain := []byte("licencia-maxmind-de-prueba")
	blob, err := Protect(plain)
	if err != nil {
		t.Skipf("Protect no disponible en este entorno (¿Keychain bloqueado?): %v", err)
	}
	if bytes.Contains(blob, plain) {
		t.Fatal("el blob protegido contiene el texto plano")
	}
	got, err := Unprotect(blob)
	if err != nil {
		t.Fatalf("Unprotect: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip = %q, want %q", got, plain)
	}
}

func TestUnprotectRejectsGarbage(t *testing.T) {
	if _, err := Unprotect([]byte("no-es-un-blob")); err == nil {
		t.Fatal("Unprotect aceptó un blob inválido")
	}
}
