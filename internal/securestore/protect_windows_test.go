//go:build windows

package securestore

import (
	"bytes"
	"testing"
)

func TestDPAPIRoundTrip(t *testing.T) {
	want := []byte("licencia-de-prueba")
	enc, err := Protect(want)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(enc, want) {
		t.Fatal("DPAPI devolvió texto plano")
	}
	got, err := Unprotect(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round trip: got %q want %q", got, want)
	}
}
