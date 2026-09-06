//go:build !windows

package systheme

import "testing"

func TestPreferenceNeverForcesLightOutsideWindows(t *testing.T) {
	if got := Preference(); got != Unknown {
		t.Errorf("Preference() on a non-Windows build = %q, want %q (must never assert a specific OS preference it can't know)", got, Unknown)
	}
}
