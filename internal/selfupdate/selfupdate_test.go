package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// Keep the locked-file retry loop fast in tests — a real deployment
	// wants a few seconds of patience for antivirus/handle-release delays,
	// a test wants the same code path exercised in milliseconds.
	replaceRetries = 3
	replaceDelay = 10 * time.Millisecond
	os.Exit(m.Run())
}

func hashOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return b
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestApplyStagesReplaceButKeepsBackupUntilFinalized(t *testing.T) {
	// Apply alone must NOT delete the backup — only FinalizeSuccess does,
	// and only once the caller has confirmed the new executable actually
	// started (audit item F.13).
	dir := t.TempDir()
	source := filepath.Join(dir, "TRAZIP-0.7.4.exe")
	target := filepath.Join(dir, "TRAZIP.exe")
	newContent := []byte("new-version-bytes")
	writeFile(t, source, newContent)
	writeFile(t, target, []byte("old-version-bytes"))

	plan, err := Apply(Args{Source: source, Target: target, ExpectedSHA256: hashOf(newContent)})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := mustRead(t, target); string(got) != string(newContent) {
		t.Errorf("target content = %q, want %q", got, newContent)
	}
	if !exists(target + ".old") {
		t.Error("expected the .old backup to still exist right after Apply, before FinalizeSuccess")
	}
	if plan.Backup == "" || !plan.TargetExisted {
		t.Errorf("plan = %+v, want Backup set and TargetExisted true", plan)
	}

	FinalizeSuccess(plan)
	if exists(target + ".old") {
		t.Error("expected the .old backup to be gone after FinalizeSuccess")
	}
}

func TestApplyFreshInstallWithNoExistingTarget(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "TRAZIP-0.7.4.exe")
	target := filepath.Join(dir, "TRAZIP-0.7.4-final.exe")
	newContent := []byte("brand-new-bytes")
	writeFile(t, source, newContent)

	plan, err := Apply(Args{Source: source, Target: target, ExpectedSHA256: hashOf(newContent)})
	if err != nil {
		t.Fatalf("Apply with no pre-existing target: %v", err)
	}
	if got := mustRead(t, target); string(got) != string(newContent) {
		t.Errorf("target content = %q, want %q", got, newContent)
	}
	if plan.TargetExisted || plan.Backup != "" {
		t.Errorf("plan = %+v, want TargetExisted false and no Backup for a fresh install", plan)
	}
}

func TestApplySourceMissing(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "TRAZIP.exe")
	writeFile(t, target, []byte("old-version-bytes"))

	_, err := Apply(Args{Source: filepath.Join(dir, "does-not-exist.exe"), Target: target, ExpectedSHA256: "aa"})
	if err == nil {
		t.Fatal("expected an error for a missing source")
	}
	if got := mustRead(t, target); string(got) != "old-version-bytes" {
		t.Error("target must be untouched when source is missing")
	}
}

func TestApplySHAMismatch(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "TRAZIP-0.7.4.exe")
	target := filepath.Join(dir, "TRAZIP.exe")
	writeFile(t, source, []byte("new-version-bytes"))
	writeFile(t, target, []byte("old-version-bytes"))

	_, err := Apply(Args{Source: source, Target: target, ExpectedSHA256: hashOf([]byte("something else entirely"))})
	if err == nil {
		t.Fatal("expected a hash mismatch error")
	}
	if got := mustRead(t, target); string(got) != "old-version-bytes" {
		t.Error("target must be untouched on a hash mismatch")
	}
	if exists(target + ".old") {
		t.Error("a hash mismatch must be caught before any rename — no .old should ever be created")
	}
}

func TestApplyTargetLockedFails(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific file locking behavior")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "TRAZIP-0.7.4.exe")
	target := filepath.Join(dir, "TRAZIP.exe")
	newContent := []byte("new-version-bytes")
	writeFile(t, source, newContent)
	writeFile(t, target, []byte("old-version-bytes"))

	locked, err := os.Open(target)
	if err != nil {
		t.Fatalf("opening target to simulate a lock: %v", err)
	}
	defer locked.Close()

	_, err = Apply(Args{Source: source, Target: target, ExpectedSHA256: hashOf(newContent)})
	if err == nil {
		t.Fatal("expected an error when the target is locked by another handle")
	}
	if got := mustRead(t, target); string(got) != "old-version-bytes" {
		t.Error("a locked target must be left completely untouched")
	}
}

func TestApplyRollsBackOnInstallFailure(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific file locking behavior")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "TRAZIP-0.7.4.exe")
	target := filepath.Join(dir, "TRAZIP.exe")
	newContent := []byte("new-version-bytes")
	writeFile(t, source, newContent)
	writeFile(t, target, []byte("old-version-bytes"))

	// Hold SOURCE open so the second rename (source -> target), which
	// happens after the target has already been backed up, fails —
	// exercising Apply's own internal rollback path rather than the
	// earlier backup step.
	locked, err := os.Open(source)
	if err != nil {
		t.Fatalf("opening source to simulate a lock: %v", err)
	}
	defer locked.Close()

	_, err = Apply(Args{Source: source, Target: target, ExpectedSHA256: hashOf(newContent)})
	if err == nil {
		t.Fatal("expected an error when the install rename fails")
	}
	if got := mustRead(t, target); string(got) != "old-version-bytes" {
		t.Errorf("target after a rolled-back failure = %q, want the original content restored", got)
	}
	if exists(target + ".old") {
		t.Error("a successful automatic rollback must not leave a .old file behind")
	}
}

func TestApplyClearsStaleBackupFromPreviousFailedAttempt(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "TRAZIP-0.7.4.exe")
	target := filepath.Join(dir, "TRAZIP.exe")
	newContent := []byte("new-version-bytes")
	writeFile(t, source, newContent)
	writeFile(t, target, []byte("old-version-bytes"))
	writeFile(t, target+".old", []byte("garbage left over from a crashed previous attempt"))

	if _, err := Apply(Args{Source: source, Target: target, ExpectedSHA256: hashOf(newContent)}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := mustRead(t, target); string(got) != string(newContent) {
		t.Errorf("target content = %q, want %q", got, newContent)
	}
}

func TestApplyRejectsSourceEqualsTarget(t *testing.T) {
	dir := t.TempDir()
	same := filepath.Join(dir, "TRAZIP.exe")
	writeFile(t, same, []byte("bytes"))
	if _, err := Apply(Args{Source: same, Target: same, ExpectedSHA256: hashOf([]byte("bytes"))}); err == nil {
		t.Error("expected an error when source and target are the same file")
	}
}

func TestApplyRejectsNonExeTarget(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "TRAZIP-0.7.4.exe")
	writeFile(t, source, []byte("bytes"))
	_, err := Apply(Args{Source: source, Target: filepath.Join(dir, "not-an-exe.txt"), ExpectedSHA256: hashOf([]byte("bytes"))})
	if err == nil {
		t.Error("expected an error for a target that doesn't look like an executable")
	}
}

func TestApplyRequiresAllArguments(t *testing.T) {
	cases := []Args{
		{Source: "", Target: "x.exe", ExpectedSHA256: "aa"},
		{Source: "x.exe", Target: "", ExpectedSHA256: "aa"},
		{Source: "x.exe", Target: "y.exe", ExpectedSHA256: ""},
	}
	for _, a := range cases {
		if _, err := Apply(a); err == nil {
			t.Errorf("Apply(%+v) succeeded, want an error for missing required fields", a)
		}
	}
}

func TestApplyPathsWithSpaces(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Program Files", "My TRAZIP App")
	source := filepath.Join(dir, "updates", "TRAZIP 0.7.4.exe")
	target := filepath.Join(dir, "TRAZIP.exe")
	newContent := []byte("spaced path bytes")
	writeFile(t, source, newContent)
	writeFile(t, target, []byte("old"))

	if _, err := Apply(Args{Source: source, Target: target, ExpectedSHA256: hashOf(newContent)}); err != nil {
		t.Fatalf("Apply with spaces in the path: %v", err)
	}
	if got := mustRead(t, target); string(got) != string(newContent) {
		t.Error("content mismatch after a replace through a path containing spaces")
	}
}

func TestApplyPathsWithUnicode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Usuários", "日本語フォルダ", "café")
	source := filepath.Join(dir, "TRAZIP-0.7.4.exe")
	target := filepath.Join(dir, "TRAZIP.exe")
	newContent := []byte("unicode path bytes")
	writeFile(t, source, newContent)
	writeFile(t, target, []byte("old"))

	if _, err := Apply(Args{Source: source, Target: target, ExpectedSHA256: hashOf(newContent)}); err != nil {
		t.Fatalf("Apply with unicode path components: %v", err)
	}
	if got := mustRead(t, target); string(got) != string(newContent) {
		t.Error("content mismatch after a replace through a unicode path")
	}
}

// TestApplyPortableStyleDoesNotTouchSiblingFiles mirrors how
// internal/update.Manager.PrepareInstall builds Args for a portable
// install: Cleanup is empty, and the only file that should ever change is
// Target itself — portable.txt, data/, capturas/ etc. must be untouched.
func TestApplyPortableStyleDoesNotTouchSiblingFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "TRAZIP.exe")
	source := filepath.Join(dir, "updates", "TRAZIP-0.7.4.exe")
	newContent := []byte("portable new bytes")
	writeFile(t, target, []byte("portable old bytes"))
	writeFile(t, source, newContent)

	marker := filepath.Join(dir, "portable.txt")
	dataFile := filepath.Join(dir, "data", "captures.db")
	capturaFile := filepath.Join(dir, "capturas", "session1.pcap")
	writeFile(t, marker, []byte("portable"))
	writeFile(t, dataFile, []byte("db-bytes"))
	writeFile(t, capturaFile, []byte("pcap-bytes"))

	plan, err := Apply(Args{Source: source, Target: target, ExpectedSHA256: hashOf(newContent)})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	FinalizeSuccess(plan)
	if got := mustRead(t, target); string(got) != string(newContent) {
		t.Error("target was not replaced with the new content")
	}
	if got := mustRead(t, marker); string(got) != "portable" {
		t.Error("portable.txt must never be touched by an update")
	}
	if got := mustRead(t, dataFile); string(got) != "db-bytes" {
		t.Error("data/ contents must never be touched by an update")
	}
	if got := mustRead(t, capturaFile); string(got) != "pcap-bytes" {
		t.Error("capturas/ contents must never be touched by an update")
	}
}

// TestApplyStandaloneStyleCleansOldNamedExeOnlyAfterFinalize mirrors
// internal/update.Manager.PrepareInstall's standalone branch: Target is a
// NEW, correctly-versioned filename (never a silent rewrite of the old
// one), and Cleanup names the old-versioned file to remove — but only
// once FinalizeSuccess confirms the new executable actually started
// (audit item F.13: never remove the old file before that's known).
func TestApplyStandaloneStyleCleansOldNamedExeOnlyAfterFinalize(t *testing.T) {
	dir := t.TempDir()
	oldExe := filepath.Join(dir, "TRAZIP-0.7.3.exe")
	source := filepath.Join(dir, "updates", "TRAZIP-0.7.4.exe")
	target := filepath.Join(dir, "TRAZIP-0.7.4.exe")
	newContent := []byte("standalone new bytes")
	writeFile(t, oldExe, []byte("standalone old bytes"))
	writeFile(t, source, newContent)

	plan, err := Apply(Args{Source: source, Target: target, Cleanup: oldExe, ExpectedSHA256: hashOf(newContent)})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := mustRead(t, target); string(got) != string(newContent) {
		t.Error("new-named target was not created with the new content")
	}
	if !exists(oldExe) {
		t.Error("the old-named standalone exe must still exist right after Apply — only FinalizeSuccess removes it")
	}

	FinalizeSuccess(plan)
	if exists(oldExe) {
		t.Error("the old-named standalone exe should be cleaned up after FinalizeSuccess")
	}
}

// --- Launch-failure / rollback (audit items F.14, F.15) ---
//
// Launch is exercised for real here (not mocked): the fixture "source"
// content is arbitrary bytes, never a valid PE executable, so a real
// exec.Command(...).Start() against it fails on Windows exactly the way a
// genuinely corrupt or incompatible download would.

func TestPortableLaunchFailureRollsBackToOriginal(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "TRAZIP-0.7.4.exe")
	target := filepath.Join(dir, "TRAZIP.exe")
	newContent := []byte("not a real executable")
	originalContent := []byte("original-not-a-real-executable-either")
	writeFile(t, source, newContent)
	writeFile(t, target, originalContent)

	plan, err := Apply(Args{Source: source, Target: target, ExpectedSHA256: hashOf(newContent)})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if err := Launch(target); err == nil {
		t.Fatal("expected Launch to fail against non-executable content")
	}
	if err := Rollback(plan); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	if got := mustRead(t, target); string(got) != string(originalContent) {
		t.Errorf("target after rollback = %q, want the original content restored", got)
	}
	if exists(target + ".old") {
		t.Error("Rollback must not leave a .old file behind after successfully restoring")
	}
}

func TestStandaloneLaunchFailureRemovesNewFileKeepsOld(t *testing.T) {
	dir := t.TempDir()
	oldExe := filepath.Join(dir, "TRAZIP-0.7.3.exe")
	source := filepath.Join(dir, "updates", "TRAZIP-0.7.4.exe")
	target := filepath.Join(dir, "TRAZIP-0.7.4.exe")
	newContent := []byte("not a real executable")
	writeFile(t, oldExe, []byte("standalone old bytes"))
	writeFile(t, source, newContent)

	plan, err := Apply(Args{Source: source, Target: target, Cleanup: oldExe, ExpectedSHA256: hashOf(newContent)})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if err := Launch(target); err == nil {
		t.Fatal("expected Launch to fail against non-executable content")
	}
	if err := Rollback(plan); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	if exists(target) {
		t.Error("the new standalone file that never started should be removed by Rollback")
	}
	if !exists(oldExe) {
		t.Error("the old standalone exe must still exist — Cleanup only ever runs from FinalizeSuccess, which never ran")
	}
	if got := mustRead(t, oldExe); string(got) != "standalone old bytes" {
		t.Error("the old standalone exe's content must be untouched")
	}
}

func TestRollbackSurfacesRestoreFailureInsteadOfSwallowingIt(t *testing.T) {
	// audit item F.14: a rollback that itself fails must return a loud,
	// explicit error — never silently pretend everything is fine.
	dir := t.TempDir()
	source := filepath.Join(dir, "TRAZIP-0.7.4.exe")
	target := filepath.Join(dir, "TRAZIP.exe")
	newContent := []byte("new bytes")
	writeFile(t, source, newContent)
	writeFile(t, target, []byte("original bytes"))

	plan, err := Apply(Args{Source: source, Target: target, ExpectedSHA256: hashOf(newContent)})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Delete the backup out from under Rollback, simulating something
	// external removing it between Apply and the caller deciding to roll
	// back — Rollback has nothing to restore from and must say so.
	if err := os.Remove(plan.Backup); err != nil {
		t.Fatalf("removing backup to simulate an external failure: %v", err)
	}

	if err := Rollback(plan); err == nil {
		t.Error("expected Rollback to report an error when its own backup is missing, not swallow it")
	}
}

func TestWaitForExitOnAlreadyExitedPID(t *testing.T) {
	// A PID essentially guaranteed not to correspond to a live process.
	if err := WaitForExit(999999, 2*time.Second); err != nil {
		t.Errorf("WaitForExit on a nonexistent PID should return immediately without error, got: %v", err)
	}
}
