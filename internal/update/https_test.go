package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireHTTPSURLAcceptsHTTPS(t *testing.T) {
	cases := []string{
		"https://example.com/file",
		"https://example.com/file?x=1&y=2",
		"https://example.com:443/file",
		"https://github.com/kerwilgil/trazip-releases/releases/download/v0.7.4/TRAZIP-0.7.4.exe",
	}
	for _, raw := range cases {
		if err := requireHTTPSURL(raw); err != nil {
			t.Errorf("requireHTTPSURL(%q) = %v, want nil", raw, err)
		}
	}
}

func TestRequireHTTPSURLRejectsHTTP(t *testing.T) {
	if err := requireHTTPSURL("http://example.com/file"); err == nil {
		t.Error("expected an error for a plain http:// URL")
	}
}

func TestRequireHTTPSURLRejectsFile(t *testing.T) {
	if err := requireHTTPSURL("file:///etc/passwd"); err == nil {
		t.Error("expected an error for a file:// URL")
	}
}

func TestRequireHTTPSURLRejectsOtherSchemes(t *testing.T) {
	cases := []string{
		"ftp://example.com/file",
		"data:text/plain,hello",
		"javascript:alert(1)",
	}
	for _, raw := range cases {
		if err := requireHTTPSURL(raw); err == nil {
			t.Errorf("requireHTTPSURL(%q) accepted a non-https scheme", raw)
		}
	}
}

func TestRequireHTTPSURLRejectsRelative(t *testing.T) {
	cases := []string{
		"relative/path",
		"//example.com/file", // scheme-relative — Scheme is empty, not https
		"/just/a/path",
	}
	for _, raw := range cases {
		if err := requireHTTPSURL(raw); err == nil {
			t.Errorf("requireHTTPSURL(%q) accepted a relative/scheme-relative URL", raw)
		}
	}
}

func TestRequireHTTPSURLRejectsMissingHost(t *testing.T) {
	if err := requireHTTPSURL("https:///missing-host"); err == nil {
		t.Error("expected an error for an https URL with no host")
	}
}

func TestRequireHTTPSURLRejectsUserInfo(t *testing.T) {
	if err := requireHTTPSURL("https://user:pass@example.com/file"); err == nil {
		t.Error("expected an error for a URL with embedded credentials")
	}
}

func TestRequireHTTPSURLRejectsMalformed(t *testing.T) {
	// A control character makes url.Parse itself fail.
	if err := requireHTTPSURL("https://example.com/\x7f"); err == nil {
		t.Error("expected an error for a malformed URL")
	}
}

// --- Pipeline-level: a plain-HTTP browser_download_url must fail closed
// before any request is attempted, for every one of the four asset kinds
// (audit item 3: update.json, update.json.sig, app exe, updater exe). ---

func TestCheckReleaseRejectsHTTPManifestURL(t *testing.T) {
	mux := http.NewServeMux()
	// A plain-HTTP server standing in for a maliciously/accidentally
	// http:// browser_download_url — checkRelease must never even reach it.
	httpSrv := httptest.NewServer(mux)
	defer httpSrv.Close()
	mux.HandleFunc("/assets/update.json", func(w http.ResponseWriter, r *http.Request) {
		t.Error("must never request update.json over plain HTTP")
	})

	tlsMux := http.NewServeMux()
	release := ghReleaseJSON("v0.8.0", false, false, map[string]string{
		"update.json":     httpSrv.URL + "/assets/update.json", // HTTP, not HTTPS
		"update.json.sig": httpSrv.URL + "/assets/update.json.sig",
	})
	tlsMux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(release) })
	tlsSrv := httptest.NewTLSServer(tlsMux)
	defer tlsSrv.Close()

	_, err := checkRelease(context.Background(), newTestHTTPClient(), tlsSrv.URL, "kerwilgil/trazip-releases", "0.7.3", "TRAZIP/0.7.3-test")
	if err == nil {
		t.Fatal("expected an error when update.json's download URL is plain HTTP")
	}
}

func TestCheckReleaseRejectsHTTPAppAssetURL(t *testing.T) {
	requireWindows(t)
	appBytes, updaterBytes := []byte("app"), []byte("updater")
	appName := expectedAppAssetName("0.8.0")
	m := validManifest("0.8.0", appBytes, updaterBytes)
	manifestBytes, sigHex := signedManifest(t, m)

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("must never request the app asset over plain HTTP")
	}))
	defer httpSrv.Close()

	tlsMux := http.NewServeMux()
	tlsMux.HandleFunc("/assets/update.json", func(w http.ResponseWriter, r *http.Request) { w.Write(manifestBytes) })
	tlsMux.HandleFunc("/assets/update.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sigHex)) })
	tlsSrv := httptest.NewTLSServer(tlsMux)
	defer tlsSrv.Close()

	release := ghReleaseJSON("v0.8.0", false, false, map[string]string{
		"update.json":     tlsSrv.URL + "/assets/update.json",
		"update.json.sig": tlsSrv.URL + "/assets/update.json.sig",
		appName:           httpSrv.URL + "/app", // HTTP, not HTTPS
		updaterAssetName:  tlsSrv.URL + "/assets/" + updaterAssetName,
	})
	tlsMux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(release) })

	_, err := checkRelease(context.Background(), newTestHTTPClient(), tlsSrv.URL, "kerwilgil/trazip-releases", "0.7.0", "TRAZIP/0.7.0-test")
	if err == nil {
		t.Fatal("expected an error when the app asset's download URL is plain HTTP")
	}
}

func TestCheckReleaseRejectsHTTPUpdaterAssetURL(t *testing.T) {
	requireWindows(t)
	appBytes, updaterBytes := []byte("app"), []byte("updater")
	appName := expectedAppAssetName("0.8.0")
	m := validManifest("0.8.0", appBytes, updaterBytes)
	manifestBytes, sigHex := signedManifest(t, m)

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("must never request the updater asset over plain HTTP")
	}))
	defer httpSrv.Close()

	tlsMux := http.NewServeMux()
	tlsMux.HandleFunc("/assets/update.json", func(w http.ResponseWriter, r *http.Request) { w.Write(manifestBytes) })
	tlsMux.HandleFunc("/assets/update.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sigHex)) })
	tlsMux.HandleFunc("/assets/"+appName, func(w http.ResponseWriter, r *http.Request) { w.Write(appBytes) })
	tlsSrv := httptest.NewTLSServer(tlsMux)
	defer tlsSrv.Close()

	release := ghReleaseJSON("v0.8.0", false, false, map[string]string{
		"update.json":     tlsSrv.URL + "/assets/update.json",
		"update.json.sig": tlsSrv.URL + "/assets/update.json.sig",
		appName:           tlsSrv.URL + "/assets/" + appName,
		updaterAssetName:  httpSrv.URL + "/updater", // HTTP, not HTTPS
	})
	tlsMux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(release) })

	_, err := checkRelease(context.Background(), newTestHTTPClient(), tlsSrv.URL, "kerwilgil/trazip-releases", "0.7.0", "TRAZIP/0.7.0-test")
	if err == nil {
		t.Fatal("expected an error when the updater asset's download URL is plain HTTP")
	}
}
