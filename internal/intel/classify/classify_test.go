package classify

import (
	"net/netip"
	"testing"

	"trazip/internal/model"
)

func hasClass(got []model.NetClass, want model.NetClass) bool {
	for _, c := range got {
		if c == want {
			return true
		}
	}
	return false
}

func TestClassify(t *testing.T) {
	cases := []struct {
		addr string
		want model.NetClass
	}{
		{"8.8.8.8", model.ClassPublic},
		{"1.1.1.1", model.ClassPublic},
		{"192.168.1.10", model.ClassPrivate},
		{"10.0.0.1", model.ClassPrivate},
		{"172.16.5.4", model.ClassPrivate},
		{"127.0.0.1", model.ClassLoopback},
		{"169.254.1.1", model.ClassLinkLocal},
		{"224.0.0.1", model.ClassMulticast},
		{"0.0.0.0", model.ClassBogon},
		{"100.64.0.1", model.ClassBogon},
		{"192.0.2.55", model.ClassDocumentation},
		{"203.0.113.9", model.ClassDocumentation},
		{"2001:4860:4860::8888", model.ClassPublic},
		{"::1", model.ClassLoopback},
		{"fe80::1", model.ClassLinkLocal},
		{"2001:db8::1", model.ClassDocumentation},
		{"fd00::1", model.ClassPrivate},
	}
	for _, tc := range cases {
		addr := netip.MustParseAddr(tc.addr)
		got := Classify(addr)
		if !hasClass(got, tc.want) {
			t.Errorf("Classify(%s) = %v, want to contain %s", tc.addr, got, tc.want)
		}
	}
}

func TestIsPublic(t *testing.T) {
	if !IsPublic(netip.MustParseAddr("8.8.8.8")) {
		t.Error("8.8.8.8 should be public")
	}
	if IsPublic(netip.MustParseAddr("192.168.0.1")) {
		t.Error("192.168.0.1 should not be public")
	}
	if IsPublic(netip.MustParseAddr("127.0.0.1")) {
		t.Error("loopback should not be public")
	}
}

func TestInvalidAddr(t *testing.T) {
	got := Classify(netip.Addr{})
	if !hasClass(got, model.ClassUnknown) {
		t.Errorf("invalid addr should be unknown, got %v", got)
	}
}
