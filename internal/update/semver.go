package update

import (
	"fmt"
	"strconv"
	"strings"
)

// version is a parsed MAJOR.MINOR.PATCH, plus one controlled exception for
// TRAZIP's own development builds: the exact suffix "-dev" (as in
// "1.4.0-dev"). It is deliberately NOT a general SemVer 2.0.0 implementation
// — no arbitrary prerelease identifiers, no build metadata, no dot-separated
// prerelease precedence. TRAZIP's published tags are plain "vX.Y.Z"; the only
// non-stable identity that ever reaches this comparison is a locally built
// binary's own "-dev" marker, so that is the only suffix accepted. Anything
// else (-rc1, -beta, +build, "-dev.foo", a bare trailing "-") is rejected.
type version struct {
	major, minor, patch int
	// dev is true for an "X.Y.Z-dev" development build. Such a build sorts
	// immediately BELOW the same X.Y.Z stable release, so a running
	// "1.4.0-dev" correctly detects a published "1.4.0" as an available
	// update, while "1.4.1-dev" still outranks a stable "1.4.0".
	dev bool
}

// parseVersion accepts "X.Y.Z" or "vX.Y.Z", each optionally carrying the
// exact suffix "-dev", with each numeric component a non-negative integer
// and no leading zeros beyond a bare "0". Anything else (missing components,
// any suffix other than "-dev", build metadata, non-numeric parts) is
// rejected — this is the boundary between "a string we were handed" and "a
// value this package's comparisons can trust", so it fails closed.
//
// Only the local current version is ever expected to carry "-dev". Release
// tags from the distribution channel are separately constrained to
// ^v\d+\.\d+\.\d+$ in client.go and never reach a comparison with a suffix;
// validateManifest additionally refuses a "-dev" manifest version outright.
func parseVersion(s string) (version, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")

	dev := false
	if rest, ok := strings.CutSuffix(s, "-dev"); ok {
		dev = true
		s = rest
	}

	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return version{}, fmt.Errorf("version %q is not MAJOR.MINOR.PATCH", s)
	}
	nums := make([]int, 3)
	for i, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') {
			return version{}, fmt.Errorf("version %q has an invalid component %q", s, p)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return version{}, fmt.Errorf("version %q has a non-numeric component %q", s, p)
		}
		nums[i] = n
	}
	return version{major: nums[0], minor: nums[1], patch: nums[2], dev: dev}, nil
}

// compareVersions returns -1, 0, or 1 as a is less than, equal to, or
// greater than b — numeric component comparison, never string/lexical
// comparison (which would wrongly rank "0.9.0" above "0.10.0"). When both
// sides share the same MAJOR.MINOR.PATCH, a "-dev" build ranks below the
// stable release of that same version.
func compareVersions(a, b string) (int, error) {
	va, err := parseVersion(a)
	if err != nil {
		return 0, err
	}
	vb, err := parseVersion(b)
	if err != nil {
		return 0, err
	}
	switch {
	case va.major != vb.major:
		return sign(va.major - vb.major), nil
	case va.minor != vb.minor:
		return sign(va.minor - vb.minor), nil
	case va.patch != vb.patch:
		return sign(va.patch - vb.patch), nil
	case va.dev != vb.dev:
		// Same MAJOR.MINOR.PATCH: the development build precedes the stable
		// release of that version, so "1.4.0-dev" < "1.4.0".
		if va.dev {
			return -1, nil
		}
		return 1, nil
	default:
		return 0, nil
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
