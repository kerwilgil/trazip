//go:build darwin

package notify

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Send shows a macOS Notification Center banner via osascript — no cgo, no
// new dependency, and it works from both the .app bundle and the bare binary.
// Errors are returned rather than logged so the caller decides whether a
// failed notification matters.
func Send(title, body string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	script := fmt.Sprintf("display notification %s with title %s",
		appleScriptString(body), appleScriptString(title))
	if out, err := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script).CombinedOutput(); err != nil {
		return fmt.Errorf("osascript: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// appleScriptString quotes s as an AppleScript string literal. AppleScript
// only escapes backslash and double quote inside string literals.
func appleScriptString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}
