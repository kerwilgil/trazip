//go:build windows

package systheme

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

// tempKeyPath returns a disposable HKCU path — never the real Personalize
// key, so these tests never touch (or change) the developer's actual
// Windows theme setting.
func tempKeyPath(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(`SOFTWARE\TRAZIP-systheme-test-%d`, rand.New(rand.NewSource(time.Now().UnixNano())).Int63())
}

func createTempKey(t *testing.T, path string, appsUseLightTheme uint32, setValue bool) {
	t.Helper()
	key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE)
	if err != nil {
		t.Fatalf("creating temp registry key: %v", err)
	}
	defer key.Close()
	if setValue {
		if err := key.SetDWordValue("AppsUseLightTheme", appsUseLightTheme); err != nil {
			t.Fatalf("setting AppsUseLightTheme: %v", err)
		}
	}
	t.Cleanup(func() {
		registry.DeleteKey(registry.CURRENT_USER, path)
	})
}

func TestPreferenceAtDarkFromRealRegistryAPI(t *testing.T) {
	path := tempKeyPath(t)
	createTempKey(t, path, 0, true) // AppsUseLightTheme=0 means dark

	if got := preferenceAt(registry.CURRENT_USER, path); got != Dark {
		t.Errorf("preferenceAt = %q, want %q", got, Dark)
	}
}

func TestPreferenceAtLightFromRealRegistryAPI(t *testing.T) {
	path := tempKeyPath(t)
	createTempKey(t, path, 1, true) // AppsUseLightTheme=1 means light

	if got := preferenceAt(registry.CURRENT_USER, path); got != Light {
		t.Errorf("preferenceAt = %q, want %q", got, Light)
	}
}

func TestPreferenceAtUnknownWhenKeyMissing(t *testing.T) {
	// A path that was never created — OpenKey must fail, never guess Light.
	path := tempKeyPath(t)
	if got := preferenceAt(registry.CURRENT_USER, path); got != Unknown {
		t.Errorf("preferenceAt for a missing key = %q, want %q", got, Unknown)
	}
}

func TestPreferenceAtUnknownWhenValueMissing(t *testing.T) {
	path := tempKeyPath(t)
	createTempKey(t, path, 0, false) // key exists, but AppsUseLightTheme is never written

	if got := preferenceAt(registry.CURRENT_USER, path); got != Unknown {
		t.Errorf("preferenceAt with no AppsUseLightTheme value = %q, want %q", got, Unknown)
	}
}

func TestPreferenceUsesTheRealPersonalizeKey(t *testing.T) {
	// Not a behavioral assertion (this machine's real theme is whatever it
	// is) — just confirms Preference() resolves to one of the three valid
	// values via the real, non-parameterized code path, and never panics.
	got := Preference()
	if got != Dark && got != Light && got != Unknown {
		t.Errorf("Preference() = %q, want one of dark/light/\"\"", got)
	}
}
