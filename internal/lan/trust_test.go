package lan

import (
	"path/filepath"
	"testing"

	"trazip/internal/probe/portscan"
)

func TestTrustStoreDetectsIdentityAndServiceDrift(t *testing.T) {
	s := NewTrustStore(filepath.Join(t.TempDir(), "trust.json"))
	base := []HostResult{{IP: "192.168.1.10", MAC: "00:11:22:33:44:55", OpenPorts: []portscan.PortResult{{Port: 80, State: "open"}}}}
	r, err := s.Assess(base)
	if err != nil || !r.BaselineCreated || len(r.Findings) != 0 {
		t.Fatalf("baseline: %+v %v", r, err)
	}
	changed := []HostResult{{IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:FF", OpenPorts: []portscan.PortResult{{Port: 443, State: "open"}}}}
	r, err = s.Assess(changed)
	if err != nil || len(r.Findings) == 0 {
		t.Fatalf("change not found: %+v %v", r, err)
	}
}
