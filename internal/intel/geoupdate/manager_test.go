package geoupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifySHA256(t *testing.T) {
	data := []byte("GeoLite2")
	sum := sha256.Sum256(data)
	if err := verifySHA256(data, []byte(fmt.Sprintf("%x  file.tar.gz", sum))); err != nil {
		t.Fatal(err)
	}
	if err := verifySHA256([]byte("alterado"), []byte(fmt.Sprintf("%x", sum))); err == nil {
		t.Fatal("aceptó contenido con checksum incorrecto")
	}
}

func TestRemoteModifiedUsesBasicAuth(t *testing.T) {
	wantTime := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "123456" || pass != "test-license" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodHead {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Last-Modified", wantTime.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	m := &Manager{client: server.Client()}
	got, err := m.remoteModified(t.Context(), server.URL, "123456", "test-license")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(wantTime) {
		t.Fatalf("Last-Modified: got %s want %s", got, wantTime)
	}
}

func TestExtractMMDBOnlyExpectedFile(t *testing.T) {
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	payload := []byte("mmdb-test")
	if err := tw.WriteHeader(&tar.Header{Name: "GeoLite2-City_20260714/GeoLite2-City.mmdb", Mode: 0o644, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path, err := extractMMDB(archive.Bytes(), dir, "GeoLite2-City.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	if filepath.Dir(path) != dir {
		t.Fatalf("archivo fuera del directorio: %s", path)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q want %q", got, payload)
	}
}
