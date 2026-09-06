//go:build !windows && !darwin

package notify

// Send is a no-op outside Windows — the in-app event feed still shows every
// monitor event, only the OS-level toast is Windows-specific for now.
func Send(title, body string) error {
	return nil
}
