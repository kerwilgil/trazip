package update

import "testing"

func TestCompareVersionsNumericNotLexical(t *testing.T) {
	// The exact case string comparison gets wrong: "0.10.0" < "0.9.0"
	// lexically, but 0.10.0 is the newer version.
	cmp, err := compareVersions("0.10.0", "0.9.0")
	if err != nil {
		t.Fatalf("compareVersions: %v", err)
	}
	if cmp <= 0 {
		t.Errorf("compareVersions(0.10.0, 0.9.0) = %d, want > 0", cmp)
	}
}

func TestCompareVersionsEqual(t *testing.T) {
	cmp, err := compareVersions("0.7.3", "0.7.3")
	if err != nil {
		t.Fatalf("compareVersions: %v", err)
	}
	if cmp != 0 {
		t.Errorf("compareVersions(0.7.3, 0.7.3) = %d, want 0", cmp)
	}
}

func TestCompareVersionsAcceptsVPrefix(t *testing.T) {
	cmp, err := compareVersions("v0.8.0", "0.7.3")
	if err != nil {
		t.Fatalf("compareVersions: %v", err)
	}
	if cmp <= 0 {
		t.Errorf("compareVersions(v0.8.0, 0.7.3) = %d, want > 0", cmp)
	}
}

func TestCompareVersionsMajorMinorPatchOrdering(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "0.9.9", 1},
		{"0.8.0", "0.7.9", 1},
		{"0.7.4", "0.7.3", 1},
		{"0.7.3", "0.7.4", -1},
		{"0.7.3", "0.8.0", -1},
		{"0.7.3", "1.0.0", -1},
	}
	for _, c := range cases {
		got, err := compareVersions(c.a, c.b)
		if err != nil {
			t.Fatalf("compareVersions(%q, %q): %v", c.a, c.b, err)
		}
		if sign(got) != c.want {
			t.Errorf("compareVersions(%q, %q) sign = %d, want %d", c.a, c.b, sign(got), c.want)
		}
	}
}

func TestParseVersionAcceptsDevSuffix(t *testing.T) {
	cases := []struct {
		in                  string
		major, minor, patch int
	}{
		{"1.4.0-dev", 1, 4, 0},
		{"v1.4.0-dev", 1, 4, 0},
		{"0.0.0-dev", 0, 0, 0},
		{"10.20.30-dev", 10, 20, 30},
	}
	for _, c := range cases {
		v, err := parseVersion(c.in)
		if err != nil {
			t.Fatalf("parseVersion(%q): %v", c.in, err)
		}
		if !v.dev {
			t.Errorf("parseVersion(%q).dev = false, want true", c.in)
		}
		if v.major != c.major || v.minor != c.minor || v.patch != c.patch {
			t.Errorf("parseVersion(%q) = %d.%d.%d, want %d.%d.%d",
				c.in, v.major, v.minor, v.patch, c.major, c.minor, c.patch)
		}
	}
}

func TestParseVersionStableHasNoDevFlag(t *testing.T) {
	for _, s := range []string{"1.4.0", "v1.4.0", "0.7.3"} {
		v, err := parseVersion(s)
		if err != nil {
			t.Fatalf("parseVersion(%q): %v", s, err)
		}
		if v.dev {
			t.Errorf("parseVersion(%q).dev = true, want false", s)
		}
	}
}

func TestCompareVersionsDevPrecedence(t *testing.T) {
	// DEV < STABLE only when MAJOR.MINOR.PATCH are identical; otherwise the
	// numeric components decide and the suffix is irrelevant.
	cases := []struct {
		a, b string
		want int
	}{
		{"1.4.0", "1.4.0-dev", 1},   // stable release outranks its own dev build
		{"1.4.0-dev", "1.4.0", -1},  // and the dev build is behind it
		{"1.4.0-dev", "1.4.0-dev", 0}, // two dev builds of the same version are equal
		{"1.4.1-dev", "1.4.0", 1},   // a newer base still wins even as a dev build
		{"1.4.0-dev", "1.3.2", 1},   // dev build of a newer minor beats an older stable
		{"1.3.2", "1.4.0-dev", -1},  // and the reverse
		{"1.4.0-dev", "1.4.1", -1},  // older base loses even against a stable newer
		{"v1.4.0", "1.4.0-dev", 1},  // v-prefix on the stable side changes nothing
	}
	for _, c := range cases {
		got, err := compareVersions(c.a, c.b)
		if err != nil {
			t.Fatalf("compareVersions(%q, %q): %v", c.a, c.b, err)
		}
		if sign(got) != c.want {
			t.Errorf("compareVersions(%q, %q) sign = %d, want %d", c.a, c.b, sign(got), c.want)
		}
	}
}

func TestParseVersionRejectsMalformed(t *testing.T) {
	bad := []string{
		"",
		"0.7",
		"1.4",           // missing PATCH
		"0.7.3.1",
		"1.4.0.0",       // too many components
		"0.7.rc1",
		"0.7.-1",
		"a.b.c",
		"foo1.4.0",      // non-numeric MAJOR
		"0.07.3",        // leading zero
		"0.7.3-rc1",
		"1.4.0-rc1",     // only "-dev" is an accepted suffix
		"1.4.0-",        // bare trailing dash
		"1.4.0-foo",
		"1.4.0-dev.foo", // "-dev" must be the whole suffix, exactly
		"1.4.0+build",   // build metadata is not supported
		"1.4.0-dev-dev", // suffix stripped once, remainder still invalid
		"-dev",
		"1.4-dev",       // "-dev" on a non MAJOR.MINOR.PATCH base
	}
	for _, s := range bad {
		if _, err := parseVersion(s); err == nil {
			t.Errorf("parseVersion(%q) succeeded, want an error", s)
		}
	}
}
