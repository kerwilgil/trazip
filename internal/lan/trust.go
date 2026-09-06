package lan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"trazip/internal/probe/portscan"
)

type TrustFinding struct {
	Level    string `json:"level"`
	Kind     string `json:"kind"`
	Identity string `json:"identity"`
	IP       string `json:"ip,omitempty"`
	MAC      string `json:"mac,omitempty"`
	Summary  string `json:"summary"`
	Evidence string `json:"evidence,omitempty"`
}

type TrustResult struct {
	BaselineCreated bool           `json:"baselineCreated"`
	KnownDevices    int            `json:"knownDevices"`
	ObservedDevices int            `json:"observedDevices"`
	Findings        []TrustFinding `json:"findings"`
	UpdatedAt       string         `json:"updatedAt"`
}

type trustRecord struct {
	Identity  string `json:"identity"`
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	OpenPorts []int  `json:"openPorts,omitempty"`
	FirstSeen string `json:"firstSeen"`
	LastSeen  string `json:"lastSeen"`
}

type TrustStore struct {
	path string
	mu   sync.Mutex
}

func NewTrustStore(path string) *TrustStore { return &TrustStore{path: path} }

func (s *TrustStore) Assess(hosts []HostResult) (TrustResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	known, err := s.load()
	if err != nil {
		return TrustResult{}, err
	}
	first := len(known) == 0
	byIP := map[string]trustRecord{}
	for _, rec := range known {
		byIP[rec.IP] = rec
	}
	findings := []TrustFinding{}
	for _, h := range hosts {
		id := identityFor(h)
		if id == "" {
			continue
		}
		ports := openPortNumbers(h.OpenPorts)
		old, exists := known[id]
		if !exists && len(known) >= 10000 {
			continue
		}
		if !exists && !first {
			f := TrustFinding{Level: "medium", Kind: "new_device", Identity: id, IP: h.IP, MAC: h.MAC, Summary: "Dispositivo no visto anteriormente en esta instalación de TRAZIP."}
			if prior, ok := byIP[h.IP]; ok && prior.Identity != id {
				f.Level = "high"
				f.Kind = "identity_changed"
				f.Evidence = "antes " + prior.Identity + ", ahora " + id
			}
			findings = append(findings, f)
		} else if exists {
			if old.IP != "" && old.IP != h.IP {
				findings = append(findings, TrustFinding{Level: "low", Kind: "ip_changed", Identity: id, IP: h.IP, MAC: h.MAC, Summary: "La identidad conocida apareció con otra IP.", Evidence: old.IP + " → " + h.IP})
			}
			if !samePorts(old.OpenPorts, ports) {
				findings = append(findings, TrustFinding{Level: "medium", Kind: "service_drift", Identity: id, IP: h.IP, MAC: h.MAC, Summary: "Cambió el conjunto de puertos abiertos observado.", Evidence: portsText(old.OpenPorts) + " → " + portsText(ports)})
			}
		}
		firstSeen := now
		if exists {
			firstSeen = old.FirstSeen
		}
		known[id] = trustRecord{Identity: id, IP: h.IP, MAC: normalizeMAC(h.MAC), Hostname: h.Hostname, OpenPorts: ports, FirstSeen: firstSeen, LastSeen: now}
	}
	if err := s.save(known); err != nil {
		return TrustResult{}, err
	}
	return TrustResult{BaselineCreated: first, KnownDevices: len(known), ObservedDevices: len(hosts), Findings: findings, UpdatedAt: now}, nil
}

func identityFor(h HostResult) string {
	if m := normalizeMAC(h.MAC); m != "" {
		return "mac:" + m
	}
	if h.IP != "" {
		return "ip:" + h.IP
	}
	return ""
}
func normalizeMAC(v string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(v), "-", ":"))
}
func openPortNumbers(in []portscan.PortResult) []int {
	out := make([]int, 0, len(in))
	for _, p := range in {
		if p.State == "open" {
			out = append(out, p.Port)
		}
	}
	sort.Ints(out)
	return out
}
func samePorts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func portsText(p []int) string { b, _ := json.Marshal(p); return string(b) }
func (s *TrustStore) load() (map[string]trustRecord, error) {
	out := map[string]trustRecord{}
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
func (s *TrustStore) save(v map[string]trustRecord) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600)
}
