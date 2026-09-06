//go:build windows

package systheme

import "golang.org/x/sys/windows/registry"

// Preference reads the same registry value Windows' own Settings > Colours
// page writes for "Choose your default app mode", so this always agrees
// with what the user actually configured there, regardless of what the
// WebView2 runtime separately reports to CSS. Returns Unknown (never a
// guessed Light) if the key or value can't be read.
func Preference() string {
	return preferenceAt(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize`)
}

// preferenceAt is Preference's testable core: root/path are parameters
// purely so tests can point it at a disposable temp key instead of the
// real Personalize key — mutating that for real would change the
// developer's actual Windows theme as a side effect of `go test`.
func preferenceAt(root registry.Key, path string) string {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return Unknown
	}
	defer key.Close()

	appsUseLightTheme, _, err := key.GetIntegerValue("AppsUseLightTheme")
	if err != nil {
		return Unknown
	}
	if appsUseLightTheme == 0 {
		return Dark
	}
	return Light
}
