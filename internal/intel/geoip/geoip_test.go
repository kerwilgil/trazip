package geoip

import (
	"net/netip"
	"testing"
)

func TestOpenMissingDatasets(t *testing.T) {
	e := Open(t.TempDir()) // empty dir: no GeoLite2-*.mmdb present
	defer e.Close()

	if e.Available() {
		t.Error("Available() should be false with no datasets")
	}
	for _, d := range e.Datasets() {
		if d.Present {
			t.Errorf("dataset %q should not be Present", d.Name)
		}
	}

	res := e.Lookup(netip.MustParseAddr("8.8.8.8"))
	if res.HasGeo || res.HasASN {
		t.Errorf("Lookup with no datasets should return empty Result, got %+v", res)
	}
}

func TestLookupInvalidAddr(t *testing.T) {
	e := Open(t.TempDir())
	defer e.Close()
	res := e.Lookup(netip.Addr{})
	if res.HasGeo || res.HasASN {
		t.Errorf("Lookup of invalid addr should be zero, got %+v", res)
	}
}
