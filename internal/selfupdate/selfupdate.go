// Package selfupdate performs the actual on-disk replacement of TRAZIP's
// own executable — the one step internal/update cannot do itself, because
// Windows will not let a running process overwrite its own binary. It has
// no network logic and trusts nothing it wasn't handed directly: the
// caller (cmd/trazip-updater) re-verifies the SHA-256 here before ever
// touching the target, exactly as if these arguments had arrived from an
// untrusted source, even though in practice they were constructed locally
// by TRAZIP's own internal/update.Manager.
package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// replaceRetries/replaceDelay bound how long Apply/Rollback retry a rename
// against a file Windows is still holding onto for a moment after the old
// TRAZIP process exits (antivirus scanning, delayed handle release).
// Package vars rather than consts so tests can shrink them instead of
// taking seconds.
var (
	replaceRetries = 10
	replaceDelay   = 300 * time.Millisecond
)

// Args are the exact, locally-constructed parameters trazip-updater acts
// on — see internal/update.UpdaterArgs, which this mirrors.
type Args struct {
	Source         string // the verified, already-downloaded new executable
	Target         string // where the running app must end up
	Cleanup        string // optional: a stale file to remove after success ("" = none)
	ExpectedSHA256 string
}

// Plan is what a successful Apply staged: the backup taken (if any) and
// the stale-file cleanup that's still pending. It is NOT yet committed —
// the caller must confirm the replaced executable actually started before
// calling FinalizeSuccess, or call Rollback if it didn't. Apply itself
// never makes that call, because it has no way to know whether Launch
// will succeed.
type Plan struct {
	Target        string
	Backup        string // "" if Target didn't exist before Apply — nothing to roll back to
	TargetExisted bool
	Cleanup       string
}

// Apply verifies Source's hash, backs up Target (if it exists), and moves
// Source into Target's place. It does NOT delete the backup and does NOT
// remove Cleanup — those only happen once the caller confirms the new
// executable actually started (FinalizeSuccess). If the replace step
// itself fails, Apply rolls back automatically before returning, since at
// that point nothing has been confirmed working yet either way.
func Apply(a Args) (Plan, error) {
	if a.Source == "" || a.Target == "" || a.ExpectedSHA256 == "" {
		return Plan{}, fmt.Errorf("source, target and expected-sha256 are all required")
	}
	source, err := filepath.Abs(a.Source)
	if err != nil {
		return Plan{}, fmt.Errorf("resolving source path: %w", err)
	}
	target, err := filepath.Abs(a.Target)
	if err != nil {
		return Plan{}, fmt.Errorf("resolving target path: %w", err)
	}
	if strings.EqualFold(source, target) {
		return Plan{}, fmt.Errorf("source and target must not be the same file")
	}
	if !strings.EqualFold(filepath.Ext(target), ".exe") {
		return Plan{}, fmt.Errorf("target %q does not look like an executable", target)
	}
	if _, err := os.Stat(source); err != nil {
		return Plan{}, fmt.Errorf("source not found: %w", err)
	}
	if err := verifySHA256(source, a.ExpectedSHA256); err != nil {
		return Plan{}, err
	}

	backup := target + ".old"
	os.Remove(backup) // clear any stale backup left by a previous failed attempt

	plan := Plan{Target: target, Cleanup: a.Cleanup}
	if _, statErr := os.Stat(target); statErr == nil {
		plan.TargetExisted = true
		plan.Backup = backup
		if err := retryRename(target, backup); err != nil {
			return Plan{}, fmt.Errorf("backing up the current executable (is TRAZIP still running?): %w", err)
		}
	}

	if err := retryRename(source, target); err != nil {
		if plan.TargetExisted {
			if rbErr := retryRename(plan.Backup, target); rbErr != nil {
				return Plan{}, fmt.Errorf("installing the new executable failed (%v), AND restoring the backup also failed (%v) — TRAZIP may be left without a working executable; restore %s manually", err, rbErr, plan.Backup)
			}
		}
		return Plan{}, fmt.Errorf("installing the new executable: %w", err)
	}
	return plan, nil
}

// FinalizeSuccess deletes the backup and any stale standalone file. Call
// only after confirming the replaced executable actually started —
// calling this before that point would throw away the only way back if
// the new executable turns out not to run at all.
func FinalizeSuccess(p Plan) {
	if p.Backup != "" {
		os.Remove(p.Backup)
	}
	if p.Cleanup != "" && !strings.EqualFold(p.Cleanup, p.Target) {
		os.Remove(p.Cleanup)
	}
}

// Rollback undoes a successful Apply when the new executable failed to
// start. If Target existed before Apply, its backup is restored in place;
// if Apply was a fresh standalone install (nothing existed at Target
// before), the new, never-successfully-started file is removed instead of
// left in place pretending to be installed. Cleanup is never touched here
// — FinalizeSuccess never ran, so whatever Cleanup pointed at (the old
// standalone exe) was never removed and needs no restoring.
//
// Returns an error — never silently swallowed — if the restore itself
// fails, since that is exactly the situation where TRAZIP could be left
// without a working executable and the caller needs to know.
func Rollback(p Plan) error {
	if !p.TargetExisted {
		if err := os.Remove(p.Target); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing the new executable at %s that failed to start: %w", p.Target, err)
		}
		return nil
	}
	if err := retryRename(p.Backup, p.Target); err != nil {
		return fmt.Errorf("restoring the previous executable from %s to %s failed: %w — the backup is still there, restore it manually", p.Backup, p.Target, err)
	}
	return nil
}

// Launch starts path as a new, independent process — used to relaunch
// TRAZIP after Apply succeeds. Its caller decides FinalizeSuccess vs
// Rollback based on whether this returns an error.
func Launch(path string) error {
	cmd := exec.Command(path)
	cmd.Dir = filepath.Dir(path)
	return cmd.Start()
}

func verifySHA256(path, expectedHex string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, expectedHex) {
		return fmt.Errorf("sha256 mismatch: got %s, want %s", got, expectedHex)
	}
	return nil
}

// retryRename retries a handful of times with a short delay — see the
// replaceRetries/replaceDelay doc comment above for why the first attempt
// failing is not necessarily permanent. Used for both the forward replace
// and any rollback restore, since a file Windows is still holding onto
// doesn't care which direction the rename is going.
func retryRename(oldpath, newpath string) error {
	var err error
	for i := 0; i < replaceRetries; i++ {
		if err = os.Rename(oldpath, newpath); err == nil {
			return nil
		}
		time.Sleep(replaceDelay)
	}
	return err
}
