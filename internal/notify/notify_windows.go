//go:build windows

// Package notify shows native OS notifications so long-running background
// watchers (Monitor) can flag events while TRAZIP is minimized. It reuses
// the toast library Wails' Windows frontend already vendors — no new
// third-party dependency enters the tree.
package notify

import (
	toast "git.sr.ht/~jackmordaunt/go-toast/v2"
)

// Send shows a Windows toast notification. Errors are returned rather than
// logged so the caller decides whether a failed notification matters — a
// monitor event must never fail because the toast subsystem did.
func Send(title, body string) error {
	n := toast.Notification{
		AppID: "TRAZIP",
		Title: title,
		Body:  body,
	}
	return n.Push()
}
