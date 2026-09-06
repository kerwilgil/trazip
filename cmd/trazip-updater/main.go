// Command trazip-updater is a small helper process with exactly one job:
// replace TRAZIP.exe's own bytes after it has exited, which Windows does
// not allow a running executable to do to itself. TRAZIP downloads and
// verifies the update entirely on its own (Ed25519-signed manifest,
// SHA-256 asset hash — see internal/update) before ever invoking this
// binary; this process independently re-verifies the hash again but has
// no network logic of its own and never parses anything remote — every
// argument it receives was constructed locally by TRAZIP, never copied
// from a server response.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"trazip/internal/selfupdate"
)

func main() {
	pid := flag.Int("pid", 0, "PID of the running TRAZIP process to wait for (0 = don't wait)")
	source := flag.String("source", "", "path to the verified, already-downloaded new executable")
	target := flag.String("target", "", "path TRAZIP should end up at")
	cleanup := flag.String("cleanup", "", "optional stale file to remove after a successful replace")
	sha256Hex := flag.String("expected-sha256", "", "expected SHA-256 of source, re-verified before install")
	restart := flag.Bool("restart", true, "relaunch target after a successful replace")
	waitTimeout := flag.Duration("wait-timeout", 30*time.Second, "how long to wait for the PID to exit")
	flag.Parse()

	if err := run(*pid, *source, *target, *cleanup, *sha256Hex, *restart, *waitTimeout); err != nil {
		fmt.Fprintln(os.Stderr, "trazip-updater: "+err.Error())
		os.Exit(1)
	}
}

func run(pid int, source, target, cleanup, expectedSHA256 string, restart bool, waitTimeout time.Duration) error {
	if pid > 0 {
		if err := selfupdate.WaitForExit(pid, waitTimeout); err != nil {
			return fmt.Errorf("waiting for pid %d to exit: %w", pid, err)
		}
	}

	plan, err := selfupdate.Apply(selfupdate.Args{
		Source:         source,
		Target:         target,
		Cleanup:        cleanup,
		ExpectedSHA256: expectedSHA256,
	})
	if err != nil {
		return err
	}

	if !restart {
		selfupdate.FinalizeSuccess(plan)
		return nil
	}

	// The replace only counts as successful once the new executable
	// actually starts — a backup that gets deleted before that point
	// would leave TRAZIP with no way back from a replace that "worked"
	// but produced something that can't run.
	if err := selfupdate.Launch(target); err != nil {
		if rbErr := selfupdate.Rollback(plan); rbErr != nil {
			return fmt.Errorf("replaced the executable but it failed to start (%v), AND rolling back also failed (%v)", err, rbErr)
		}
		return fmt.Errorf("replaced the executable but it failed to start; rolled back to the previous version: %w", err)
	}
	selfupdate.FinalizeSuccess(plan)
	return nil
}
