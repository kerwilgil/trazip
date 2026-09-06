package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

// newTestHTTPClient mirrors production's newHTTPClient (same timeout, same
// httpsOnlyRedirect policy) but trusts any TLS server's certificate,
// self-signed included — httptest.NewTLSServer mints a fresh self-signed
// cert per test, and tests care about exercising the real HTTPS-only
// policy, not about certificate validity, which production's real
// TLS-terminated GitHub connection already gets from the OS trust store.
func newTestHTTPClient() *http.Client {
	return &http.Client{
		Timeout: apiTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: httpsOnlyRedirect(maxRedirects),
	}
}

// signedManifest builds a valid update.json + hex signature for the given
// fields, swapping the package's trusted public key for the test's
// duration so nothing here depends on (or risks confusion with) the real
// embedded production key.
func signedManifest(t *testing.T, m Manifest) (manifestBytes []byte, sigHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	orig := publicKey
	publicKey = pub
	t.Cleanup(func() { publicKey = orig })

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, data)
	return data, hex.EncodeToString(sig)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// validManifest builds a Manifest that passes validateManifest for the
// given version, with fake app+updater bytes sized/hashed correctly. Only
// meaningful on windows/amd64, matching this repo's only shipped target.
func validManifest(version string, appBytes, updaterBytes []byte) Manifest {
	return Manifest{
		Version: version,
		Channel: stableChannel,
		Windows: map[string]PlatformAssets{
			"amd64": {
				App:     ManifestAsset{Asset: expectedAppAssetName(version), SHA256: sha256Hex(appBytes), Size: int64(len(appBytes))},
				Updater: ManifestAsset{Asset: updaterAssetName, SHA256: sha256Hex(updaterBytes), Size: int64(len(updaterBytes))},
			},
		},
	}
}

// ghReleaseJSON builds a minimal GitHub releases/latest response body.
func ghReleaseJSON(tag string, draft, prerelease bool, assets map[string]string) []byte {
	type asset struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	}
	var as []asset
	for name, url := range assets {
		// Size 0 deliberately: most tests here don't care about the
		// manifest/GitHub size cross-check (checkRelease only compares
		// when GitHub reports a size > 0) — see ghReleaseJSONWithSizes
		// for tests that specifically exercise that check.
		as = append(as, asset{Name: name, BrowserDownloadURL: url, Size: 0})
	}
	body := struct {
		TagName     string    `json:"tag_name"`
		Draft       bool      `json:"draft"`
		Prerelease  bool      `json:"prerelease"`
		PublishedAt time.Time `json:"published_at"`
		Assets      []asset   `json:"assets"`
	}{TagName: tag, Draft: draft, Prerelease: prerelease, PublishedAt: time.Now(), Assets: as}
	data, _ := json.Marshal(body)
	return data
}

// ghReleaseJSONWithSizes is ghReleaseJSON but lets a test declare each
// asset's GitHub-reported size explicitly, for the manifest/GitHub size
// cross-check tests.
func ghReleaseJSONWithSizes(tag string, assets map[string]struct {
	URL  string
	Size int64
}) []byte {
	type asset struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	}
	var as []asset
	for name, a := range assets {
		as = append(as, asset{Name: name, BrowserDownloadURL: a.URL, Size: a.Size})
	}
	body := struct {
		TagName string  `json:"tag_name"`
		Assets  []asset `json:"assets"`
	}{TagName: tag, Assets: as}
	data, _ := json.Marshal(body)
	return data
}

func requireWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		t.Skip("asset-selection path is windows/amd64-specific; skipping on " + runtime.GOOS + "/" + runtime.GOARCH)
	}
}

// fixtureFullRelease spins up one httptest.Server serving a complete,
// self-consistent release: signed update.json + .sig, app bytes, updater
// bytes, at "v"+version. Returns the server and the raw asset byte
// contents so a test can assert against them.
type fullReleaseFixture struct {
	srv          *httptest.Server
	appBytes     []byte
	updaterBytes []byte
}

func newFullReleaseFixture(t *testing.T, version string) *fullReleaseFixture {
	t.Helper()
	requireWindows(t)

	appBytes := []byte("fake-trazip-exe-bytes-for-" + version)
	updaterBytes := []byte("fake-trazip-updater-exe-bytes-for-" + version)
	appName := expectedAppAssetName(version)

	manifest := validManifest(version, appBytes, updaterBytes)
	manifestBytes, sigHex := signedManifest(t, manifest)

	mux := http.NewServeMux()
	mux.HandleFunc("/assets/update.json", func(w http.ResponseWriter, r *http.Request) { w.Write(manifestBytes) })
	mux.HandleFunc("/assets/update.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sigHex)) })
	mux.HandleFunc("/assets/"+appName, func(w http.ResponseWriter, r *http.Request) { w.Write(appBytes) })
	mux.HandleFunc("/assets/"+updaterAssetName, func(w http.ResponseWriter, r *http.Request) { w.Write(updaterBytes) })
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	release := ghReleaseJSON("v"+version, false, false, map[string]string{
		"update.json":     srv.URL + "/assets/update.json",
		"update.json.sig": srv.URL + "/assets/update.json.sig",
		appName:           srv.URL + "/assets/" + appName,
		updaterAssetName:  srv.URL + "/assets/" + updaterAssetName,
	})
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(release) })

	return &fullReleaseFixture{srv: srv, appBytes: appBytes, updaterBytes: updaterBytes}
}

func TestCheckReleaseNoUpdateWhenEqual(t *testing.T) {
	fx := newFullReleaseFixture(t, "0.7.3")
	info, err := checkRelease(context.Background(), newTestHTTPClient(), fx.srv.URL, "kerwilgil/trazip-releases", "0.7.3", "TRAZIP/0.7.3-test")
	if err != nil {
		t.Fatalf("checkRelease: %v", err)
	}
	if info.Available {
		t.Errorf("expected no update when latest == current, got Available=true (%+v)", info)
	}
}

func TestCheckReleaseUpdateAvailable(t *testing.T) {
	fx := newFullReleaseFixture(t, "0.7.4")
	info, err := checkRelease(context.Background(), newTestHTTPClient(), fx.srv.URL, "kerwilgil/trazip-releases", "0.7.3", "TRAZIP/0.7.3-test")
	if err != nil {
		t.Fatalf("checkRelease: %v", err)
	}
	if !info.Available {
		t.Fatalf("expected an update to be available, got %+v", info)
	}
	if info.LatestVersion != "0.7.4" {
		t.Errorf("LatestVersion = %q, want 0.7.4", info.LatestVersion)
	}
	if info.Asset.Name != "TRAZIP-0.7.4.exe" || info.Asset.SHA256 != sha256Hex(fx.appBytes) {
		t.Errorf("Asset = %+v, mismatched name/hash", info.Asset)
	}
	if info.UpdaterAsset.Name != "trazip-updater.exe" || info.UpdaterAsset.SHA256 != sha256Hex(fx.updaterBytes) {
		t.Errorf("UpdaterAsset = %+v, mismatched name/hash", info.UpdaterAsset)
	}
}

func TestCheckReleaseDevBuildSeesStableRelease(t *testing.T) {
	// A locally built "1.4.0-dev" binary must recognise the published
	// stable "1.4.0" as an available update — the case that previously
	// failed with a raw "invalid component" parse error in Settings.
	fx := newFullReleaseFixture(t, "1.4.0")
	info, err := checkRelease(context.Background(), newTestHTTPClient(), fx.srv.URL, "kerwilgil/trazip-releases", "1.4.0-dev", "TRAZIP/1.4.0-dev-test")
	if err != nil {
		t.Fatalf("checkRelease for a -dev current version: %v", err)
	}
	if !info.Available {
		t.Fatalf("expected stable 1.4.0 to be offered to a 1.4.0-dev build, got %+v", info)
	}
	if info.LatestVersion != "1.4.0" || info.CurrentVersion != "1.4.0-dev" {
		t.Errorf("info = {current:%q latest:%q}, want {1.4.0-dev 1.4.0}", info.CurrentVersion, info.LatestVersion)
	}
}

func TestCheckReleaseDevBuildNoUpdateAgainstSameStable(t *testing.T) {
	// Once "1.4.0" ships, a still-"1.4.0-dev" build sees it as newer (the
	// test above); a build already at stable "1.4.0" must see nothing.
	fx := newFullReleaseFixture(t, "1.4.0")
	info, err := checkRelease(context.Background(), newTestHTTPClient(), fx.srv.URL, "kerwilgil/trazip-releases", "1.4.0", "TRAZIP/1.4.0-test")
	if err != nil {
		t.Fatalf("checkRelease: %v", err)
	}
	if info.Available {
		t.Errorf("expected no update when current == latest stable, got %+v", info)
	}
}

func TestValidateManifestRejectsDevVersion(t *testing.T) {
	// parseVersion tolerates "-dev" for local-vs-stable ordering, but a
	// signed manifest that declares a development version has no meaning on
	// the stable channel and must be refused outright.
	appBytes, updaterBytes := []byte("app"), []byte("updater")
	m := validManifest("1.4.0-dev", appBytes, updaterBytes)
	if _, _, err := validateManifest(&m, "amd64"); err == nil {
		t.Error("validateManifest accepted a -dev manifest version, want rejection")
	}
}

func TestCheckReleasePrereleaseIgnoredOnStableChannel(t *testing.T) {
	mux := http.NewServeMux()
	release := ghReleaseJSON("v0.8.0-rc1", false, true, nil) // prerelease=true
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(release) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	_, err := checkRelease(context.Background(), newTestHTTPClient(), srv.URL, "kerwilgil/trazip-releases", "0.7.3", "TRAZIP/0.7.3-test")
	if err == nil {
		t.Error("expected a prerelease to be rejected on the stable channel")
	}
}

func TestCheckReleaseDraftIgnored(t *testing.T) {
	mux := http.NewServeMux()
	release := ghReleaseJSON("v0.8.0", true, false, nil) // draft=true
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(release) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	_, err := checkRelease(context.Background(), newTestHTTPClient(), srv.URL, "kerwilgil/trazip-releases", "0.7.3", "TRAZIP/0.7.3-test")
	if err == nil {
		t.Error("expected a draft release to be rejected")
	}
}

func TestCheckReleaseMalformedJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{not valid json"))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	_, err := checkRelease(context.Background(), newTestHTTPClient(), srv.URL, "kerwilgil/trazip-releases", "0.7.3", "TRAZIP/0.7.3-test")
	if err == nil {
		t.Error("expected an error for malformed release JSON")
	}
}

func TestCheckReleaseHTTP404(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	_, err := checkRelease(context.Background(), newTestHTTPClient(), srv.URL, "kerwilgil/trazip-releases", "0.7.3", "TRAZIP/0.7.3-test")
	if err == nil {
		t.Error("expected an error for HTTP 404 (e.g. distribution repo not created yet)")
	}
}

func TestCheckReleaseHTTP500(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	_, err := checkRelease(context.Background(), newTestHTTPClient(), srv.URL, "kerwilgil/trazip-releases", "0.7.3", "TRAZIP/0.7.3-test")
	if err == nil {
		t.Error("expected an error for HTTP 500")
	}
}

func TestCheckReleaseTimeout(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := checkRelease(ctx, newTestHTTPClient(), srv.URL, "kerwilgil/trazip-releases", "0.7.3", "TRAZIP/0.7.3-test")
	if err == nil {
		t.Error("expected a timeout error")
	}
}

func TestCheckReleaseOversizedManifestRejected(t *testing.T) {
	huge := strings.Repeat("a", int(maxJSONBytes)+1024)
	mux := http.NewServeMux()
	mux.HandleFunc("/assets/update.json", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(huge)) })
	mux.HandleFunc("/assets/update.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("00")) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	release := ghReleaseJSON("v0.8.0", false, false, map[string]string{
		"update.json":     srv.URL + "/assets/update.json",
		"update.json.sig": srv.URL + "/assets/update.json.sig",
	})
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(release) })

	_, err := checkRelease(context.Background(), newTestHTTPClient(), srv.URL, "kerwilgil/trazip-releases", "0.7.3", "TRAZIP/0.7.3-test")
	if err == nil {
		t.Error("expected an error for an oversized update.json")
	}
}

func TestCheckReleaseMissingAssetRejected(t *testing.T) {
	manifest := validManifest("0.8.0", []byte("app"), []byte("updater"))
	manifestBytes, sigHex := signedManifest(t, manifest)
	mux := http.NewServeMux()
	mux.HandleFunc("/assets/update.json", func(w http.ResponseWriter, r *http.Request) { w.Write(manifestBytes) })
	mux.HandleFunc("/assets/update.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sigHex)) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	// Release deliberately omits the app asset from its assets list.
	release := ghReleaseJSON("v0.8.0", false, false, map[string]string{
		"update.json":     srv.URL + "/assets/update.json",
		"update.json.sig": srv.URL + "/assets/update.json.sig",
	})
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(release) })

	_, err := checkRelease(context.Background(), newTestHTTPClient(), srv.URL, "kerwilgil/trazip-releases", "0.7.3", "TRAZIP/0.7.3-test")
	if err == nil {
		t.Error("expected an error when the manifest references an asset missing from the release")
	}
}

func TestCheckReleaseDuplicateAssetRejected(t *testing.T) {
	manifest := validManifest("0.8.0", []byte("app"), []byte("updater"))
	manifestBytes, sigHex := signedManifest(t, manifest)
	mux := http.NewServeMux()
	mux.HandleFunc("/assets/update.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sigHex)) })
	mux.HandleFunc("/assets/update.json.a", func(w http.ResponseWriter, r *http.Request) { w.Write(manifestBytes) })
	mux.HandleFunc("/assets/update.json.b", func(w http.ResponseWriter, r *http.Request) { w.Write(manifestBytes) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	type asset struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	}
	body := struct {
		TagName    string  `json:"tag_name"`
		Draft      bool    `json:"draft"`
		Prerelease bool    `json:"prerelease"`
		Assets     []asset `json:"assets"`
	}{
		TagName: "v0.8.0",
		Assets: []asset{
			{Name: "update.json", BrowserDownloadURL: srv.URL + "/assets/update.json.a"},
			{Name: "update.json", BrowserDownloadURL: srv.URL + "/assets/update.json.b"}, // duplicate name
			{Name: "update.json.sig", BrowserDownloadURL: srv.URL + "/assets/update.json.sig"},
		},
	}
	data, _ := json.Marshal(body)
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(data) })

	_, err := checkRelease(context.Background(), newTestHTTPClient(), srv.URL, "kerwilgil/trazip-releases", "0.7.3", "TRAZIP/0.7.3-test")
	if err == nil {
		t.Error("expected an error when the release has a duplicate asset name")
	}
}

func TestCheckReleaseNeverDowngrades(t *testing.T) {
	// "Latest" release reports an OLDER version than what's installed --
	// must never be offered as an update, even though the manifest itself
	// verifies fine.
	fx := newFullReleaseFixture(t, "0.7.0")
	info, err := checkRelease(context.Background(), newTestHTTPClient(), fx.srv.URL, "kerwilgil/trazip-releases", "0.7.3", "TRAZIP/0.7.3-test")
	if err != nil {
		t.Fatalf("checkRelease: %v", err)
	}
	if info.Available {
		t.Error("must never report a downgrade as Available")
	}
}

func TestCheckReleaseTamperedManifestSignatureRejected(t *testing.T) {
	manifest := validManifest("0.8.0", []byte("app"), []byte("updater"))
	manifestBytes, sigHex := signedManifest(t, manifest)
	// Serve a DIFFERENT manifest body than the one that was signed.
	tampered := append([]byte(nil), manifestBytes...)
	tampered = append(tampered, ' ') // any byte change invalidates the signature

	mux := http.NewServeMux()
	mux.HandleFunc("/assets/update.json", func(w http.ResponseWriter, r *http.Request) { w.Write(tampered) })
	mux.HandleFunc("/assets/update.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sigHex)) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	release := ghReleaseJSON("v0.8.0", false, false, map[string]string{
		"update.json":     srv.URL + "/assets/update.json",
		"update.json.sig": srv.URL + "/assets/update.json.sig",
	})
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(release) })

	_, err := checkRelease(context.Background(), newTestHTTPClient(), srv.URL, "kerwilgil/trazip-releases", "0.7.3", "TRAZIP/0.7.3-test")
	if err == nil {
		t.Error("expected a signature verification failure for a tampered manifest")
	}
}

func TestCheckReleaseWrongTagFormatRejected(t *testing.T) {
	mux := http.NewServeMux()
	release := ghReleaseJSON("latest", false, false, nil) // not a vX.Y.Z tag
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(release) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	_, err := checkRelease(context.Background(), newTestHTTPClient(), srv.URL, "kerwilgil/trazip-releases", "0.7.3", "TRAZIP/0.7.3-test")
	if err == nil {
		t.Error("expected an error for a malformed tag name")
	}
}

// --- Manifest field validation (audit item B.5) ---

func TestCheckReleaseRejectsWrongChannel(t *testing.T) {
	m := validManifest("0.8.0", []byte("app"), []byte("updater"))
	m.Channel = "beta"
	assertManifestRejected(t, m)
}

func TestCheckReleaseRejectsMalformedVersion(t *testing.T) {
	m := validManifest("0.8.0", []byte("app"), []byte("updater"))
	m.Version = "0.8"
	assertManifestRejected(t, m)
}

func TestCheckReleaseRejectsBadSHA256Length(t *testing.T) {
	m := validManifest("0.8.0", []byte("app"), []byte("updater"))
	pa := m.Windows["amd64"]
	pa.App.SHA256 = "deadbeef"
	m.Windows["amd64"] = pa
	assertManifestRejected(t, m)
}

func TestCheckReleaseRejectsZeroSize(t *testing.T) {
	m := validManifest("0.8.0", []byte("app"), []byte("updater"))
	pa := m.Windows["amd64"]
	pa.App.Size = 0
	m.Windows["amd64"] = pa
	assertManifestRejected(t, m)
}

func TestCheckReleaseRejectsNegativeSize(t *testing.T) {
	m := validManifest("0.8.0", []byte("app"), []byte("updater"))
	pa := m.Windows["amd64"]
	pa.App.Size = -1
	m.Windows["amd64"] = pa
	assertManifestRejected(t, m)
}

func TestCheckReleaseRejectsOversizedDeclaredSize(t *testing.T) {
	m := validManifest("0.8.0", []byte("app"), []byte("updater"))
	pa := m.Windows["amd64"]
	pa.App.Size = maxDownloadBytes + 1
	m.Windows["amd64"] = pa
	assertManifestRejected(t, m)
}

func TestCheckReleaseRejectsNonHTTPSNotesURL(t *testing.T) {
	m := validManifest("0.8.0", []byte("app"), []byte("updater"))
	m.NotesURL = "javascript:alert(1)"
	assertManifestRejected(t, m)
}

func TestCheckReleaseRejectsNotesURLOffOfficialChannel(t *testing.T) {
	m := validManifest("0.8.0", []byte("app"), []byte("updater"))
	m.NotesURL = "https://evil.example.com/notes"
	assertManifestRejected(t, m)
}

func TestCheckReleaseAcceptsNotesURLOnOfficialChannel(t *testing.T) {
	requireWindows(t)
	appBytes, updaterBytes := []byte("app"), []byte("updater")
	m := validManifest("0.8.0", appBytes, updaterBytes)
	m.NotesURL = "https://github.com/kerwilgil/trazip-releases/releases/tag/v0.8.0"
	manifestBytes, sigHex := signedManifest(t, m)

	mux := http.NewServeMux()
	appName := expectedAppAssetName("0.8.0")
	mux.HandleFunc("/assets/update.json", func(w http.ResponseWriter, r *http.Request) { w.Write(manifestBytes) })
	mux.HandleFunc("/assets/update.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sigHex)) })
	mux.HandleFunc("/assets/"+appName, func(w http.ResponseWriter, r *http.Request) { w.Write(appBytes) })
	mux.HandleFunc("/assets/"+updaterAssetName, func(w http.ResponseWriter, r *http.Request) { w.Write(updaterBytes) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	release := ghReleaseJSON("v0.8.0", false, false, map[string]string{
		"update.json":     srv.URL + "/assets/update.json",
		"update.json.sig": srv.URL + "/assets/update.json.sig",
		appName:           srv.URL + "/assets/" + appName,
		updaterAssetName:  srv.URL + "/assets/" + updaterAssetName,
	})
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(release) })

	info, err := checkRelease(context.Background(), newTestHTTPClient(), srv.URL, "kerwilgil/trazip-releases", "0.7.3", "TRAZIP/0.7.3-test")
	if err != nil {
		t.Fatalf("checkRelease with an official-channel notesUrl: %v", err)
	}
	if !info.Available {
		t.Fatal("expected an update to be available")
	}
}

// assertManifestRejected serves m (freshly signed) as the only asset in a
// release and expects checkRelease to fail closed.
func assertManifestRejected(t *testing.T, m Manifest) {
	t.Helper()
	manifestBytes, sigHex := signedManifest(t, m)
	mux := http.NewServeMux()
	mux.HandleFunc("/assets/update.json", func(w http.ResponseWriter, r *http.Request) { w.Write(manifestBytes) })
	mux.HandleFunc("/assets/update.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sigHex)) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	release := ghReleaseJSON("v"+m.Version, false, false, map[string]string{
		"update.json":     srv.URL + "/assets/update.json",
		"update.json.sig": srv.URL + "/assets/update.json.sig",
	})
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(release) })

	_, err := checkRelease(context.Background(), newTestHTTPClient(), srv.URL, "kerwilgil/trazip-releases", "0.7.0", "TRAZIP/0.7.0-test")
	if err == nil {
		t.Errorf("expected checkRelease to reject manifest %+v", m)
	}
}

// --- Manifest/GitHub size cross-check (audit item B.6) ---

func TestCheckReleaseRejectsGitHubSizeMismatch(t *testing.T) {
	requireWindows(t)
	appBytes, updaterBytes := []byte("app-bytes"), []byte("updater-bytes")
	appName := expectedAppAssetName("0.8.0")
	m := validManifest("0.8.0", appBytes, updaterBytes)
	manifestBytes, sigHex := signedManifest(t, m)

	mux := http.NewServeMux()
	mux.HandleFunc("/assets/update.json", func(w http.ResponseWriter, r *http.Request) { w.Write(manifestBytes) })
	mux.HandleFunc("/assets/update.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sigHex)) })
	mux.HandleFunc("/assets/"+appName, func(w http.ResponseWriter, r *http.Request) { w.Write(appBytes) })
	mux.HandleFunc("/assets/"+updaterAssetName, func(w http.ResponseWriter, r *http.Request) { w.Write(updaterBytes) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	// The release itself reports a DIFFERENT size for the app asset than
	// the signed manifest declares.
	release := ghReleaseJSONWithSizes("v0.8.0", map[string]struct {
		URL  string
		Size int64
	}{
		"update.json":     {srv.URL + "/assets/update.json", 10},
		"update.json.sig": {srv.URL + "/assets/update.json.sig", 10},
		appName:           {srv.URL + "/assets/" + appName, int64(len(appBytes)) + 999},
		updaterAssetName:  {srv.URL + "/assets/" + updaterAssetName, int64(len(updaterBytes))},
	})
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(release) })

	_, err := checkRelease(context.Background(), newTestHTTPClient(), srv.URL, "kerwilgil/trazip-releases", "0.7.0", "TRAZIP/0.7.0-test")
	if err == nil {
		t.Error("expected an error when GitHub's reported size disagrees with the signed manifest's size")
	}
}
