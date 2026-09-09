package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestManager(currentVersion, downloadDir, apiBase string) *Manager {
	return newTestManagerWithSettings(currentVersion, downloadDir, apiBase, "")
}

func newTestManagerWithSettings(currentVersion, downloadDir, apiBase, settingsPath string) *Manager {
	return &Manager{
		currentVersion: currentVersion,
		channel:        ChannelConfigForLegacy(),
		apiBase:        apiBase,
		userAgent:      "TRAZIP/" + currentVersion + "-test",
		downloadDir:    downloadDir,
		settingsPath:   settingsPath,
		httpClient:     newTestHTTPClient(),
		status:         StatusIdle,
		autoCheck:      true,
		highestSeen:    currentVersion,
	}
}

func TestManagerCheckTransitionsToAvailable(t *testing.T) {
	fx := newFullReleaseFixture(t, "0.7.4")
	m := newTestManager("0.7.3", t.TempDir(), fx.srv.URL)

	info, err := m.Check(context.Background(), false)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !info.Available {
		t.Fatalf("expected an update to be available, got %+v", info)
	}
	snap := m.Snapshot()
	if snap.Status != StatusAvailable {
		t.Errorf("status = %s, want %s", snap.Status, StatusAvailable)
	}
	if snap.LastCheck.IsZero() {
		t.Error("LastCheck was not recorded")
	}
}

func TestManagerCheckTransitionsToIdleWhenNoUpdate(t *testing.T) {
	fx := newFullReleaseFixture(t, "0.7.3")
	m := newTestManager("0.7.3", t.TempDir(), fx.srv.URL)

	info, err := m.Check(context.Background(), false)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if info.Available {
		t.Fatal("expected no update when latest == current")
	}
	if snap := m.Snapshot(); snap.Status != StatusIdle {
		t.Errorf("status = %s, want %s", snap.Status, StatusIdle)
	}
}

func TestManagerCheckSkipsNetworkWithinCacheWindow(t *testing.T) {
	fx := newFullReleaseFixture(t, "0.7.4")
	m := newTestManager("0.7.3", t.TempDir(), fx.srv.URL)

	if _, err := m.Check(context.Background(), false); err != nil {
		t.Fatalf("first Check: %v", err)
	}
	fx.srv.Close() // if a second Check hits the network at all, this proves it

	info, err := m.Check(context.Background(), false)
	if err != nil {
		t.Fatalf("cached Check should not touch the network: %v", err)
	}
	if !info.Available {
		t.Error("cached Check returned a different result than the first one")
	}
}

func TestManagerCheckForceBypassesCache(t *testing.T) {
	fx := newFullReleaseFixture(t, "0.7.4")
	m := newTestManager("0.7.3", t.TempDir(), fx.srv.URL)
	if _, err := m.Check(context.Background(), false); err != nil {
		t.Fatalf("first Check: %v", err)
	}
	fx.srv.Close()

	if _, err := m.Check(context.Background(), true); err == nil {
		t.Error("force=true must hit the network even within the cache window; expected an error against the closed server")
	}
}

func TestManagerCheckNetworkFailureStaysIdleNotError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	m := newTestManager("0.7.3", t.TempDir(), srv.URL)
	if _, err := m.Check(context.Background(), false); err == nil {
		t.Fatal("expected an error from Check")
	}
	snap := m.Snapshot()
	if snap.Status != StatusIdle {
		t.Errorf("a routine check failure must leave status Idle, not %s — it must never look like a verified-update failure", snap.Status)
	}
	if snap.Error == "" {
		t.Error("expected the error to still be recorded in the snapshot")
	}
}

func TestManagerDownloadFullSuccessPath(t *testing.T) {
	fx := newFullReleaseFixture(t, "0.7.4")
	dir := t.TempDir()
	m := newTestManager("0.7.3", dir, fx.srv.URL)

	if _, err := m.Check(context.Background(), false); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := m.Download(context.Background()); err != nil {
		t.Fatalf("Download: %v", err)
	}

	snap := m.Snapshot()
	if snap.Status != StatusReady {
		t.Fatalf("status = %s, want %s", snap.Status, StatusReady)
	}
	if snap.InstallPath == "" {
		t.Fatal("InstallPath was not set")
	}
	if snap.UpdaterPath == "" {
		t.Fatal("UpdaterPath was not set")
	}
	if filepath.Ext(snap.InstallPath) != ".exe" || filepath.Ext(snap.UpdaterPath) != ".exe" {
		t.Errorf("InstallPath/UpdaterPath = %q/%q, expected final .exe files, not .partial", snap.InstallPath, snap.UpdaterPath)
	}
	got, err := os.ReadFile(snap.InstallPath)
	if err != nil {
		t.Fatalf("reading installed app file: %v", err)
	}
	if string(got) != string(fx.appBytes) {
		t.Error("downloaded app file content does not match the asset served")
	}
	gotUpdater, err := os.ReadFile(snap.UpdaterPath)
	if err != nil {
		t.Fatalf("reading installed updater file: %v", err)
	}
	if string(gotUpdater) != string(fx.updaterBytes) {
		t.Error("downloaded updater file content does not match the asset served")
	}
	if snap.Downloaded != snap.Total {
		t.Errorf("Downloaded=%d, Total=%d after a successful download, want them equal", snap.Downloaded, snap.Total)
	}
}

func TestManagerDownloadRequiresAvailableStatus(t *testing.T) {
	m := newTestManager("0.7.3", t.TempDir(), "http://unused.invalid")
	if err := m.Download(context.Background()); err == nil {
		t.Error("Download must fail when status is Idle (no prior successful Check)")
	}
}

// managerSlowFixture builds a release whose app-asset handler blocks on a
// channel, so a test can cancel mid-transfer deterministically.
type managerSlowFixture struct {
	srv   *httptest.Server
	block chan struct{}
}

func newManagerSlowFixture(t *testing.T, version string) *managerSlowFixture {
	t.Helper()
	requireWindows(t)
	appBytes := []byte("slow-app-bytes")
	updaterBytes := []byte("slow-updater-bytes")
	appName := expectedAppAssetName(version)
	m := validManifest(version, appBytes, updaterBytes)
	manifestBytes, sigHex := signedManifest(t, m)
	block := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/assets/update.json", func(w http.ResponseWriter, r *http.Request) { w.Write(manifestBytes) })
	mux.HandleFunc("/assets/update.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sigHex)) })
	mux.HandleFunc("/assets/"+appName, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("partial-"))
		w.(http.Flusher).Flush()
		<-block
	})
	mux.HandleFunc("/assets/"+updaterAssetName, func(w http.ResponseWriter, r *http.Request) { w.Write(updaterBytes) })
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(func() { srv.Close() })

	release := ghReleaseJSON("v"+version, false, false, map[string]string{
		"update.json":     srv.URL + "/assets/update.json",
		"update.json.sig": srv.URL + "/assets/update.json.sig",
		appName:           srv.URL + "/assets/" + appName,
		updaterAssetName:  srv.URL + "/assets/" + updaterAssetName,
	})
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(release) })

	return &managerSlowFixture{srv: srv, block: block}
}

func TestManagerCancelDuringDownloadReturnsToAvailableWithNoError(t *testing.T) {
	fx := newManagerSlowFixture(t, "0.8.0")
	defer close(fx.block)

	dir := t.TempDir()
	m := newTestManager("0.7.3", dir, fx.srv.URL)
	if _, err := m.Check(context.Background(), false); err != nil {
		t.Fatalf("Check: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- m.Download(context.Background()) }()
	time.Sleep(100 * time.Millisecond)
	m.Cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected Download to return an error after Cancel")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Download did not return after Cancel")
	}

	snap := m.Snapshot()
	if snap.Status != StatusAvailable {
		t.Errorf("status after a cancelled download = %s, want %s (retryable)", snap.Status, StatusAvailable)
	}
	// A deliberate user cancellation must never look like a real failure —
	// audit item G.17: "Cancelled: Available, Error=''".
	if snap.Error != "" {
		t.Errorf("Error after a user cancellation = %q, want empty (not an alarming failure)", snap.Error)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		t.Errorf("expected no leftover file after cancellation, found %s", e.Name())
	}
}

func TestManagerDownloadRealFailureLeavesVisibleError(t *testing.T) {
	// A hash mismatch is a real failure, not a cancellation — Error must
	// stay populated so Settings can show the user why it failed
	// (audit item G.17).
	requireWindows(t)
	appBytes := []byte("app-bytes")
	updaterBytes := []byte("updater-bytes")
	version := "0.8.0"
	appName := expectedAppAssetName(version)
	m := validManifest(version, appBytes, updaterBytes)
	manifestBytes, sigHex := signedManifest(t, m)

	mux := http.NewServeMux()
	mux.HandleFunc("/assets/update.json", func(w http.ResponseWriter, r *http.Request) { w.Write(manifestBytes) })
	mux.HandleFunc("/assets/update.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sigHex)) })
	// Serves DIFFERENT bytes than what the manifest's hash promises.
	mux.HandleFunc("/assets/"+appName, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("not-the-real-app-bytes")) })
	mux.HandleFunc("/assets/"+updaterAssetName, func(w http.ResponseWriter, r *http.Request) { w.Write(updaterBytes) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	release := ghReleaseJSON("v"+version, false, false, map[string]string{
		"update.json":     srv.URL + "/assets/update.json",
		"update.json.sig": srv.URL + "/assets/update.json.sig",
		appName:           srv.URL + "/assets/" + appName,
		updaterAssetName:  srv.URL + "/assets/" + updaterAssetName,
	})
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(release) })

	dir := t.TempDir()
	mgr := newTestManager("0.7.3", dir, srv.URL)
	if _, err := mgr.Check(context.Background(), false); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := mgr.Download(context.Background()); err == nil {
		t.Fatal("expected a hash-mismatch error from Download")
	}

	snap := mgr.Snapshot()
	if snap.Status != StatusAvailable {
		t.Errorf("status after a failed download = %s, want %s", snap.Status, StatusAvailable)
	}
	if snap.Error == "" {
		t.Error("expected a visible error after a real download failure, got empty")
	}
}

// TestManagerDownloadOneGoodOneBadAssetLeavesNothingBehind is audit item
// M's "one good / one bad -> NOT READY, partial cleanup both assets": the
// app asset downloads and verifies fine, but the updater asset's bytes
// don't match its signed hash. StatusReady must never be reached with only
// half of what an install needs, and neither the completed app file nor
// any .partial should be left on disk.
func TestManagerDownloadOneGoodOneBadAssetLeavesNothingBehind(t *testing.T) {
	requireWindows(t)
	appBytes := []byte("good-app-bytes")
	updaterBytes := []byte("good-updater-bytes")
	version := "0.8.0"
	appName := expectedAppAssetName(version)
	m := validManifest(version, appBytes, updaterBytes)
	manifestBytes, sigHex := signedManifest(t, m)

	mux := http.NewServeMux()
	mux.HandleFunc("/assets/update.json", func(w http.ResponseWriter, r *http.Request) { w.Write(manifestBytes) })
	mux.HandleFunc("/assets/update.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sigHex)) })
	mux.HandleFunc("/assets/"+appName, func(w http.ResponseWriter, r *http.Request) { w.Write(appBytes) }) // matches its signed hash
	mux.HandleFunc("/assets/"+updaterAssetName, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("NOT the bytes the manifest's hash promises"))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	release := ghReleaseJSON("v"+version, false, false, map[string]string{
		"update.json":     srv.URL + "/assets/update.json",
		"update.json.sig": srv.URL + "/assets/update.json.sig",
		appName:           srv.URL + "/assets/" + appName,
		updaterAssetName:  srv.URL + "/assets/" + updaterAssetName,
	})
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(release) })

	dir := t.TempDir()
	mgr := newTestManager("0.7.3", dir, srv.URL)
	if _, err := mgr.Check(context.Background(), false); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := mgr.Download(context.Background()); err == nil {
		t.Fatal("expected Download to fail when the updater asset's hash doesn't match")
	}

	snap := mgr.Snapshot()
	if snap.Status == StatusReady {
		t.Error("must never reach StatusReady with only one of the two required assets verified")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		t.Errorf("expected no leftover file after a partial failure (app succeeded, updater didn't), found %s", e.Name())
	}
}

// TestManagerCancelDuringUpdaterStageCleansUpAppToo confirms cancellation
// during the SECOND download (the updater, after the app already
// finished) still removes the already-downloaded app file — a cancelled
// download must never leave a half-complete pair behind.
func TestManagerCancelDuringUpdaterStageCleansUpAppToo(t *testing.T) {
	requireWindows(t)
	appBytes := []byte("good-app-bytes")
	updaterBytes := []byte("good-updater-bytes")
	version := "0.8.0"
	appName := expectedAppAssetName(version)
	m := validManifest(version, appBytes, updaterBytes)
	manifestBytes, sigHex := signedManifest(t, m)
	block := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/assets/update.json", func(w http.ResponseWriter, r *http.Request) { w.Write(manifestBytes) })
	mux.HandleFunc("/assets/update.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sigHex)) })
	mux.HandleFunc("/assets/"+appName, func(w http.ResponseWriter, r *http.Request) { w.Write(appBytes) })
	mux.HandleFunc("/assets/"+updaterAssetName, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("partial-"))
		w.(http.Flusher).Flush()
		<-block
	})
	srv := httptest.NewTLSServer(mux)
	defer func() { close(block); srv.Close() }()
	release := ghReleaseJSON("v"+version, false, false, map[string]string{
		"update.json":     srv.URL + "/assets/update.json",
		"update.json.sig": srv.URL + "/assets/update.json.sig",
		appName:           srv.URL + "/assets/" + appName,
		updaterAssetName:  srv.URL + "/assets/" + updaterAssetName,
	})
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) { w.Write(release) })

	dir := t.TempDir()
	mgr := newTestManager("0.7.3", dir, srv.URL)
	if _, err := mgr.Check(context.Background(), false); err != nil {
		t.Fatalf("Check: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- mgr.Download(context.Background()) }()
	// Give the app download time to finish and the updater download time
	// to start (and block).
	time.Sleep(200 * time.Millisecond)
	mgr.Cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected Download to return an error after Cancel")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Download did not return after Cancel")
	}

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		t.Errorf("expected no leftover file after cancelling mid-updater-download, found %s", e.Name())
	}
}

func TestManagerCancelIsNoOpWithoutDownload(t *testing.T) {
	m := newTestManager("0.7.3", t.TempDir(), "http://unused.invalid")
	m.Cancel() // must not panic
}

func TestManagerPrepareInstallRequiresReadyStatus(t *testing.T) {
	m := newTestManager("0.7.3", t.TempDir(), "http://unused.invalid")
	if _, err := m.PrepareInstall(`C:\TRAZIP\TRAZIP.exe`, true); err == nil {
		t.Error("PrepareInstall must fail before a verified download reaches StatusReady")
	}
}

func TestManagerPrepareInstallDoesNotChangeStatus(t *testing.T) {
	// Audit item G.16: PrepareInstall must not move Status to Installing —
	// only MarkInstalling does, and only once the caller actually spawned
	// the updater process successfully.
	fx := newFullReleaseFixture(t, "0.7.4")
	dir := t.TempDir()
	m := newTestManager("0.7.3", dir, fx.srv.URL)
	if _, err := m.Check(context.Background(), false); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := m.Download(context.Background()); err != nil {
		t.Fatalf("Download: %v", err)
	}
	if _, err := m.PrepareInstall(`C:\Portable\TRAZIP.exe`, true); err != nil {
		t.Fatalf("PrepareInstall: %v", err)
	}
	if snap := m.Snapshot(); snap.Status != StatusReady {
		t.Errorf("status after PrepareInstall alone = %s, want %s (still Ready, retryable)", snap.Status, StatusReady)
	}
}

func TestManagerMarkInstallingTransitionsFromReady(t *testing.T) {
	fx := newFullReleaseFixture(t, "0.7.4")
	dir := t.TempDir()
	m := newTestManager("0.7.3", dir, fx.srv.URL)
	if _, err := m.Check(context.Background(), false); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := m.Download(context.Background()); err != nil {
		t.Fatalf("Download: %v", err)
	}
	m.MarkInstalling()
	if snap := m.Snapshot(); snap.Status != StatusInstalling {
		t.Errorf("status after MarkInstalling = %s, want %s", snap.Status, StatusInstalling)
	}
}

func TestManagerMarkInstallingNoOpOutsideReady(t *testing.T) {
	m := newTestManager("0.7.3", t.TempDir(), "http://unused.invalid")
	m.MarkInstalling() // status is Idle; must not fabricate an Installing state
	if snap := m.Snapshot(); snap.Status != StatusIdle {
		t.Errorf("status = %s, want %s (MarkInstalling must be a no-op outside Ready)", snap.Status, StatusIdle)
	}
}

func TestManagerPrepareInstallPortableReplacesInPlace(t *testing.T) {
	fx := newFullReleaseFixture(t, "0.7.4")
	dir := t.TempDir()
	m := newTestManager("0.7.3", dir, fx.srv.URL)
	if _, err := m.Check(context.Background(), false); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := m.Download(context.Background()); err != nil {
		t.Fatalf("Download: %v", err)
	}

	currentExe := `C:\Portable\TRAZIP.exe`
	args, err := m.PrepareInstall(currentExe, true)
	if err != nil {
		t.Fatalf("PrepareInstall: %v", err)
	}
	if args.Final != currentExe {
		t.Errorf("portable Final = %q, want the running exe's own path %q", args.Final, currentExe)
	}
	if args.Cleanup != "" {
		t.Errorf("portable install should never need cleanup of a second file, got %q", args.Cleanup)
	}
	if args.ExpectedSHA256 != sha256Hex(fx.appBytes) {
		t.Error("ExpectedSHA256 does not match the verified download")
	}
	if args.UpdaterPath == "" {
		t.Error("UpdaterPath was not set — standalone installs can't rely on a pre-existing helper")
	}
}

func TestManagerPrepareInstallStandaloneKeepsNewNameAndCleansOld(t *testing.T) {
	fx := newFullReleaseFixture(t, "0.7.4")
	dir := t.TempDir()
	m := newTestManager("0.7.3", dir, fx.srv.URL)
	if _, err := m.Check(context.Background(), false); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := m.Download(context.Background()); err != nil {
		t.Fatalf("Download: %v", err)
	}

	currentExe := `C:\Users\kerwil\Downloads\TRAZIP-0.7.3.exe`
	args, err := m.PrepareInstall(currentExe, false)
	if err != nil {
		t.Fatalf("PrepareInstall: %v", err)
	}
	wantFinal := filepath.Join(filepath.Dir(currentExe), "TRAZIP-0.7.4.exe")
	if args.Final != wantFinal {
		t.Errorf("standalone Final = %q, want %q (never silently rewrite the old-named file)", args.Final, wantFinal)
	}
	if args.Cleanup != currentExe {
		t.Errorf("standalone Cleanup = %q, want the old exe %q removed once safe", args.Cleanup, currentExe)
	}
	if args.UpdaterPath == "" {
		t.Error("UpdaterPath was not set — a standalone .exe has no pre-existing helper to fall back on")
	}
}

func TestManagerPersistsLastCheckAndInfoAcrossInstances(t *testing.T) {
	fx := newFullReleaseFixture(t, "0.7.4")
	settingsPath := filepath.Join(t.TempDir(), "update-settings.json")
	m1 := newTestManagerWithSettings("0.7.3", t.TempDir(), fx.srv.URL, settingsPath)
	if _, err := m1.Check(context.Background(), false); err != nil {
		t.Fatalf("first manager's Check: %v", err)
	}

	// Use the same legacy channel config to ensure cache compatibility
	m2, err := NewManagerWithConfig(UpdateConfig{
		CurrentVersion: "0.7.3",
		DownloadDir:    t.TempDir(),
		SettingsPath:   settingsPath,
		Channel:        ChannelConfigForLegacy(),
	})
	if err != nil {
		t.Fatalf("NewManagerWithConfig: %v", err)
	}
	// Force the persisted lastCheck to look recent so the cache-skip
	// condition in Check actually engages against a server that would
	// otherwise prove it was reached.
	fx.srv.Close()

	info, err := m2.Check(context.Background(), false)
	if err != nil {
		t.Fatalf("a fresh Manager for the same version should reuse the persisted result: %v", err)
	}
	if !info.Available || info.LatestVersion != "0.7.4" {
		t.Errorf("restored info = %+v, want the persisted 0.7.4 availability", info)
	}
}

func TestManagerDiscardsStaleInfoAfterVersionChanges(t *testing.T) {
	fx := newFullReleaseFixture(t, "0.7.4")
	settingsPath := filepath.Join(t.TempDir(), "update-settings.json")
	m1 := newTestManagerWithSettings("0.7.3", t.TempDir(), fx.srv.URL, settingsPath)
	if _, err := m1.Check(context.Background(), false); err != nil {
		t.Fatalf("first manager's Check: %v", err)
	}

	// Simulate having actually installed 0.7.4 since that cache was
	// written — a Manager constructed for the NEW current version must
	// not trust a cache that says "0.7.4 is available" when 0.7.4 is
	// already what's running.
	m2 := NewManager("0.7.4", t.TempDir(), settingsPath)
	snap := m2.Snapshot()
	if snap.Info != nil {
		t.Errorf("expected no cached info to survive a version change, got %+v", snap.Info)
	}
	if !snap.LastCheck.IsZero() {
		t.Error("expected lastCheck to be discarded along with the stale info")
	}
}

func TestManagerSetAutoCheckPersists(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "update-settings.json")
	m1 := newTestManagerWithSettings("0.7.3", t.TempDir(), "http://unused.invalid", settingsPath)
	if !m1.AutoCheck() {
		t.Fatal("expected auto-check to default to true")
	}
	if err := m1.SetAutoCheck(false); err != nil {
		t.Fatalf("SetAutoCheck: %v", err)
	}

	m2 := NewManager("0.7.3", t.TempDir(), settingsPath)
	if m2.AutoCheck() {
		t.Error("a fresh Manager should load the persisted auto-check=false")
	}
}

// --- Replay protection (audit item H.18) ---

func TestManagerRejectsReplayOfOlderSignedRelease(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "update-settings.json")

	// Day 1: the client genuinely observes a signed 0.7.6 release.
	fxHigh := newFullReleaseFixture(t, "0.7.6")
	m1 := newTestManagerWithSettings("0.7.4", t.TempDir(), fxHigh.srv.URL, settingsPath)
	info, err := m1.Check(context.Background(), false)
	if err != nil {
		t.Fatalf("first Check (0.7.6): %v", err)
	}
	if !info.Available || info.LatestVersion != "0.7.6" {
		t.Fatalf("expected 0.7.6 to be available, got %+v", info)
	}

	// Day 2 (a fresh Manager loading the same persisted settings, same as
	// a real app restart): a replayed/older-but-still-genuinely-signed
	// 0.7.5 shows up. 0.7.5 > current (0.7.4), so the plain downgrade
	// check wouldn't catch it — only comparing against the highest
	// version ever observed does.
	m2 := NewManager("0.7.4", t.TempDir(), settingsPath)
	fxReplay := newFullReleaseFixture(t, "0.7.5")
	m2.apiBase = fxReplay.srv.URL
	m2.httpClient = newTestHTTPClient() // NewManager's own client won't trust the TLS test fixture's self-signed cert

	_, err = m2.Check(context.Background(), true) // force: bypass the 24h cache, we want a real network hit
	if err == nil {
		t.Fatal("expected the replayed 0.7.5 release to be rejected")
	}
	snap := m2.Snapshot()
	if snap.Status != StatusIdle {
		t.Errorf("status after a rejected replay = %s, want %s", snap.Status, StatusIdle)
	}
}

func TestManagerReplayProtectionSurvivesRestart(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "update-settings.json")

	fxHigh := newFullReleaseFixture(t, "0.7.6")
	m1 := newTestManagerWithSettings("0.7.4", t.TempDir(), fxHigh.srv.URL, settingsPath)
	if _, err := m1.Check(context.Background(), false); err != nil {
		t.Fatalf("first Check (0.7.6): %v", err)
	}

	// A brand-new Manager built through the real constructor (simulating
	// an app restart) must load highestSeen from the SAME settings file
	// and still remember 0.7.6 was already observed.
	m2 := NewManager("0.7.4", t.TempDir(), settingsPath)
	if m2.highestSeen != "0.7.6" {
		t.Fatalf("NewManager did not load persisted highestSeen: got %q, want 0.7.6", m2.highestSeen)
	}
	fxReplay := newFullReleaseFixture(t, "0.7.5")
	m2.apiBase = fxReplay.srv.URL
	m2.httpClient = newTestHTTPClient() // NewManager's own client won't trust the TLS test fixture's self-signed cert

	_, err := m2.Check(context.Background(), true)
	if err == nil {
		t.Error("expected replay protection to survive a restart via persisted settings")
	}
}

func TestManagerDevBuildAcceptsStableReleaseNotTreatedAsReplay(t *testing.T) {
	// highestSeen is initialised from currentVersion, so a dev build carries
	// "1.4.0-dev" into replay protection. The published stable "1.4.0" is
	// newer than that dev marker and must be accepted, not rejected as a
	// downgrade, and highestSeen must advance to the stable version.
	fx := newFullReleaseFixture(t, "1.4.0")
	m := newTestManager("1.4.0-dev", t.TempDir(), fx.srv.URL)
	if m.highestSeen != "1.4.0-dev" {
		t.Fatalf("precondition: highestSeen = %q, want 1.4.0-dev", m.highestSeen)
	}

	info, err := m.Check(context.Background(), true)
	if err != nil {
		t.Fatalf("Check with highestSeen=1.4.0-dev: %v", err)
	}
	if !info.Available || info.LatestVersion != "1.4.0" {
		t.Fatalf("expected stable 1.4.0 to be available, got %+v", info)
	}
	if m.highestSeen != "1.4.0" {
		t.Errorf("highestSeen = %q after accepting 1.4.0, want 1.4.0", m.highestSeen)
	}
	if snap := m.Snapshot(); snap.Status != StatusAvailable {
		t.Errorf("status = %s, want %s", snap.Status, StatusAvailable)
	}
}

func TestManagerDevBuildReplayRatchetStillHolds(t *testing.T) {
	// The replay ratchet must keep working when highestSeen originated from
	// a "1.4.0-dev" build: after observing a genuine signed 1.4.2, a later
	// replayed-but-genuine 1.4.1 (newer than the dev current, so "available",
	// yet older than highestSeen) must be refused.
	settingsPath := filepath.Join(t.TempDir(), "update-settings.json")
	fxHigh := newFullReleaseFixture(t, "1.4.2")
	m1 := newTestManagerWithSettings("1.4.0-dev", t.TempDir(), fxHigh.srv.URL, settingsPath)
	if _, err := m1.Check(context.Background(), true); err != nil {
		t.Fatalf("first Check (1.4.2): %v", err)
	}

	m2 := NewManager("1.4.0-dev", t.TempDir(), settingsPath)
	if m2.highestSeen != "1.4.2" {
		t.Fatalf("NewManager did not load persisted highestSeen: got %q, want 1.4.2", m2.highestSeen)
	}
	fxReplay := newFullReleaseFixture(t, "1.4.1")
	m2.apiBase = fxReplay.srv.URL
	m2.httpClient = newTestHTTPClient()

	if _, err := m2.Check(context.Background(), true); err == nil {
		t.Error("expected the replayed 1.4.1 release to be rejected after 1.4.2 was seen")
	}
	if snap := m2.Snapshot(); snap.Status != StatusIdle {
		t.Errorf("status after a rejected replay = %s, want %s", snap.Status, StatusIdle)
	}
}

func TestManagerAcceptsGenuineNewerReleaseAboveHighestSeen(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "update-settings.json")

	fx1 := newFullReleaseFixture(t, "0.7.5")
	m1 := newTestManagerWithSettings("0.7.4", t.TempDir(), fx1.srv.URL, settingsPath)
	if _, err := m1.Check(context.Background(), false); err != nil {
		t.Fatalf("first Check (0.7.5): %v", err)
	}

	// A genuinely NEWER release than anything seen so far must still be
	// accepted — replay protection must never become a one-way ratchet
	// that blocks real progress.
	fx2 := newFullReleaseFixture(t, "0.7.6")
	m2 := newTestManagerWithSettings("0.7.4", t.TempDir(), fx2.srv.URL, settingsPath)
	m2.httpClient = newTestHTTPClient() // NewManager's own client won't trust the TLS test fixture's self-signed cert

	info, err := m2.Check(context.Background(), true)
	if err != nil {
		t.Fatalf("expected a genuinely newer release to be accepted: %v", err)
	}
	if info.LatestVersion != "0.7.6" {
		t.Errorf("LatestVersion = %q, want 0.7.6", info.LatestVersion)
	}
}
