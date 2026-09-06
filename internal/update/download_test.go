package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestDownloadAssetSuccessAndHashVerify(t *testing.T) {
	body := []byte("this is the fake TRAZIP.exe payload")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	dir := t.TempDir()
	path, err := downloadAsset(context.Background(), srv.Client(), srv.URL, dir, "TRAZIP-0.7.4.exe", int64(len(body)), nil)
	if err != nil {
		t.Fatalf("downloadAsset: %v", err)
	}
	if filepath.Base(path) != "TRAZIP-0.7.4.exe.partial" {
		t.Errorf("downloadAsset wrote %q, want a .partial file", path)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading downloaded file: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("downloaded content = %q, want %q", got, body)
	}

	if err := verifyFileSHA256(path, sha256Hex(body)); err != nil {
		t.Errorf("verifyFileSHA256 on a correct hash: %v", err)
	}
	if err := verifyFileSHA256(path, "0000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Error("verifyFileSHA256 accepted a wrong hash — must reject")
	}
}

func TestDownloadAssetRejectsSizeMismatchUnderCap(t *testing.T) {
	// A signed manifest's Size is exactly as trustworthy as its SHA-256:
	// a body that fits comfortably under the cap but doesn't match the
	// EXACT declared size must still be rejected (audit item B.6).
	body := []byte("shorter than declared")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	dir := t.TempDir()
	_, err := downloadAsset(context.Background(), srv.Client(), srv.URL, dir, "TRAZIP-mismatch.exe", int64(len(body))+50, nil)
	if err == nil {
		t.Fatal("expected an error when the downloaded size does not exactly match the declared size")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("expected no leftover .partial after a size mismatch, found %v", entries)
	}
}

func TestDownloadAssetRejectsDeclaredOversizeBeforeRequest(t *testing.T) {
	called := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	dir := t.TempDir()
	_, err := downloadAsset(context.Background(), srv.Client(), srv.URL, dir, "TRAZIP-huge.exe", maxDownloadBytes+1, nil)
	if err == nil {
		t.Fatal("expected an error for a manifest-declared size over the cap")
	}
	if called {
		t.Error("downloadAsset made an HTTP request despite the declared size already exceeding the cap")
	}
}

func TestDownloadAssetRejectsOversizedBodyAndCleansUpPartial(t *testing.T) {
	// Server lies about Content-Length via chunked transfer and just streams
	// more than the cap regardless of what downloadAsset expected.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10") // also lies about size, on top of exceeding the cap
		w.(http.Flusher).Flush()
		chunk := make([]byte, 64*1024)
		var sent int64
		for sent < maxDownloadBytes+1024 {
			n, err := w.Write(chunk)
			sent += int64(n)
			if err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	_, err := downloadAsset(context.Background(), srv.Client(), srv.URL, dir, "TRAZIP-oversized.exe", 10, nil)
	if err == nil {
		t.Fatal("expected an error for a body larger than the download cap")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("expected no leftover files after an oversized download, found %v", entries)
	}
}

func TestDownloadAssetCancelledLeavesNoPartial(t *testing.T) {
	blockUntilCancel := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("first chunk"))
		w.(http.Flusher).Flush()
		<-blockUntilCancel // hold the connection open until the test cancels
	}))
	defer func() {
		close(blockUntilCancel)
		srv.Close()
	}()

	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		_, err := downloadAsset(ctx, srv.Client(), srv.URL, dir, "TRAZIP-cancel.exe", 1000, nil)
		done <- err
	}()

	time.Sleep(100 * time.Millisecond) // let the first chunk land
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected downloadAsset to return an error after cancellation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("downloadAsset did not return after context cancellation")
	}

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		t.Errorf("expected no .partial left behind after cancellation, found %s", e.Name())
	}
}

func TestDownloadAssetNoGoroutineLeakAfterCancel(t *testing.T) {
	blockUntilCancel := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("chunk"))
		w.(http.Flusher).Flush()
		<-blockUntilCancel
	}))
	defer func() {
		close(blockUntilCancel)
		srv.Close()
	}()

	before := runtime.NumGoroutine()

	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		downloadAsset(ctx, srv.Client(), srv.URL, dir, "TRAZIP-leak.exe", 1000, nil)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	// Give the runtime a moment to actually reclaim the goroutine stack;
	// this is inherently a little fuzzy, so allow a small margin rather
	// than requiring an exact match.
	var after int
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		after = runtime.NumGoroutine()
		if after <= before+1 {
			break
		}
	}
	if after > before+1 {
		t.Errorf("goroutine count grew after a cancelled download: before=%d after=%d", before, after)
	}
}

func TestVerifyFileSHA256MissingFile(t *testing.T) {
	if err := verifyFileSHA256(filepath.Join(t.TempDir(), "does-not-exist"), "aa"); err == nil {
		t.Error("expected an error for a missing file")
	}
}
