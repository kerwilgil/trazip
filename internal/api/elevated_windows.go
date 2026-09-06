//go:build windows

package api

import "golang.org/x/sys/windows"

// detectElevated reports whether the process runs with an elevated token.
func detectElevated() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0) // current process token
	member, err := token.IsMember(sid)
	return err == nil && member
}
