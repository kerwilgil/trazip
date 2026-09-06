package update

import "testing"

func TestExpectedAppAssetName(t *testing.T) {
	if got := expectedAppAssetName("0.7.5"); got != "TRAZIP-0.7.5.exe" {
		t.Errorf("expectedAppAssetName(0.7.5) = %q, want TRAZIP-0.7.5.exe", got)
	}
}

// TestValidateManifestAssetRejectsHostileNames is audit item B.4's exact
// reject list: an exact-match comparison against a locally-computed
// expected name means every one of these is rejected for the same simple
// reason (the string doesn't equal the expected string), not because of
// any pattern-specific sanitization that could itself have a gap.
func TestValidateManifestAssetRejectsHostileNames(t *testing.T) {
	want := "TRAZIP-0.7.5.exe"
	hostile := []string{
		"../x.exe",
		"..\\x.exe",
		`C:\x.exe`,
		`\\server\x.exe`,
		"foo/bar.exe",
		"foo\\bar.exe",
		"TRAZIP.exe",
		"otro.exe",
		"TRAZIP-0.7.4.exe", // right shape, wrong version
		"TRAZIP-0.7.5.exe ",
		" TRAZIP-0.7.5.exe",
		"TRAZIP-0.7.5.EXE",
		"trazip-0.7.5.exe",
	}
	for _, name := range hostile {
		a := ManifestAsset{Asset: name, SHA256: validSHA256, Size: 100}
		if err := validateManifestAsset(a, want); err == nil {
			t.Errorf("validateManifestAsset accepted hostile name %q", name)
		}
	}
}

func TestValidateManifestAssetAcceptsExactMatch(t *testing.T) {
	a := ManifestAsset{Asset: "TRAZIP-0.7.5.exe", SHA256: validSHA256, Size: 100}
	if err := validateManifestAsset(a, "TRAZIP-0.7.5.exe"); err != nil {
		t.Errorf("validateManifestAsset rejected the exact expected name: %v", err)
	}
}

const validSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestValidateManifestAssetRejectsBadHash(t *testing.T) {
	cases := []string{
		"deadbeef",             // too short
		validSHA256 + "a",      // too long
		"gg" + validSHA256[2:], // non-hex characters
		"",
	}
	for _, sha := range cases {
		a := ManifestAsset{Asset: "TRAZIP-0.7.5.exe", SHA256: sha, Size: 100}
		if err := validateManifestAsset(a, "TRAZIP-0.7.5.exe"); err == nil {
			t.Errorf("validateManifestAsset accepted malformed sha256 %q", sha)
		}
	}
}

func TestValidateManifestAssetRejectsBadSize(t *testing.T) {
	cases := []int64{0, -1, maxDownloadBytes + 1}
	for _, size := range cases {
		a := ManifestAsset{Asset: "TRAZIP-0.7.5.exe", SHA256: validSHA256, Size: size}
		if err := validateManifestAsset(a, "TRAZIP-0.7.5.exe"); err == nil {
			t.Errorf("validateManifestAsset accepted size %d", size)
		}
	}
}

func TestValidateNotesURLRejectsNonOfficialSchemes(t *testing.T) {
	cases := []string{
		"javascript:alert(1)",
		"data:text/html,x",
		"file:///etc/passwd",
		"http://github.com/kerwilgil/trazip-releases/x", // right host, wrong scheme
		"https://evil.example.com/x",
		"https://github.com.evil.com/kerwilgil/trazip-releases/x",
	}
	for _, url := range cases {
		if err := validateNotesURL(url); err == nil {
			t.Errorf("validateNotesURL accepted %q", url)
		}
	}
}

func TestValidateNotesURLAcceptsOfficialChannel(t *testing.T) {
	if err := validateNotesURL("https://github.com/kerwilgil/trazip-releases/releases/tag/v0.8.0"); err != nil {
		t.Errorf("validateNotesURL rejected the official channel: %v", err)
	}
}

func TestValidateManifestRejectsWrongChannel(t *testing.T) {
	m := validManifest("0.8.0", []byte("app"), []byte("updater"))
	m.Channel = "nightly"
	if _, _, err := validateManifest(&m, "amd64"); err == nil {
		t.Error("expected an error for a non-stable channel")
	}
}

func TestValidateManifestRejectsMissingArch(t *testing.T) {
	m := validManifest("0.8.0", []byte("app"), []byte("updater"))
	if _, _, err := validateManifest(&m, "arm64"); err == nil {
		t.Error("expected an error when the requested arch has no manifest entry")
	}
}

func TestValidateManifestAcceptsWellFormed(t *testing.T) {
	m := validManifest("0.8.0", []byte("app"), []byte("updater"))
	app, updater, err := validateManifest(&m, "amd64")
	if err != nil {
		t.Fatalf("validateManifest: %v", err)
	}
	if app.Asset != "TRAZIP-0.8.0.exe" {
		t.Errorf("app.Asset = %q", app.Asset)
	}
	if updater.Asset != "trazip-updater.exe" {
		t.Errorf("updater.Asset = %q", updater.Asset)
	}
}
