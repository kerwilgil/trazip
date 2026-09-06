package wifi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type PostureFinding struct {
	Level    string `json:"level"`
	Category string `json:"category"`
	SSID     string `json:"ssid,omitempty"`
	BSSID    string `json:"bssid,omitempty"`
	Summary  string `json:"summary"`
	Evidence string `json:"evidence,omitempty"`
}

type PostureResult struct {
	Score           int              `json:"score"`
	Networks        int              `json:"networks"`
	BaselineCreated bool             `json:"baselineCreated"`
	Findings        []PostureFinding `json:"findings"`
	AssessedAt      string           `json:"assessedAt"`
}

type PostureStore struct {
	path string
	mu   sync.Mutex
}

func NewPostureStore(path string) *PostureStore { return &PostureStore{path: path} }

func (s *PostureStore) Assess(networks []Network) (PostureResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	known, err := s.load()
	if err != nil {
		return PostureResult{}, err
	}
	first := len(known) == 0
	r := PostureResult{Score: 100, Networks: len(networks), BaselineCreated: first, AssessedAt: time.Now().UTC().Format(time.RFC3339)}
	for _, n := range networks {
		sec := strings.ToLower(n.Security)
		switch {
		case strings.Contains(sec, "abierta") || strings.Contains(sec, "ninguno"):
			r.Score -= 30
			r.Findings = append(r.Findings, PostureFinding{Level: "high", Category: "open_network", SSID: n.SSID, BSSID: n.BSSID, Summary: "Red WiFi sin cifrado", Evidence: n.Security})
		case strings.Contains(sec, "wep"):
			r.Score -= 30
			r.Findings = append(r.Findings, PostureFinding{Level: "high", Category: "legacy_crypto", SSID: n.SSID, BSSID: n.BSSID, Summary: "Cifrado WEP obsoleto", Evidence: n.Security})
		case strings.Contains(sec, "wpa ") || strings.Contains(sec, "wpa-") || strings.Contains(sec, "tkip"):
			r.Score -= 15
			r.Findings = append(r.Findings, PostureFinding{Level: "medium", Category: "legacy_crypto", SSID: n.SSID, BSSID: n.BSSID, Summary: "Seguridad WiFi heredada", Evidence: n.Security})
		}
		if n.APCount > 1 {
			r.Findings = append(r.Findings, PostureFinding{Level: "info", Category: "multiple_bssid", SSID: n.SSID, BSSID: n.BSSID, Summary: "SSID anunciado por múltiples AP/BSSID", Evidence: itoaPosture(n.APCount) + " AP observados; valide que pertenezcan a su infraestructura."})
		}
		b := strings.ToLower(strings.TrimSpace(n.BSSID))
		if b != "" {
			_, exists := known[b]
			if !exists && !first {
				r.Findings = append(r.Findings, PostureFinding{Level: "low", Category: "new_bssid", SSID: n.SSID, BSSID: n.BSSID, Summary: "BSSID no visto en escaneos WiFi anteriores"})
			}
			if exists || len(known) < 10000 {
				known[b] = r.AssessedAt
			}
		}
	}
	if r.Score < 0 {
		r.Score = 0
	}
	if err = s.save(known); err != nil {
		return PostureResult{}, err
	}
	return r, nil
}
func itoaPosture(n int) string { b, _ := json.Marshal(n); return string(b) }
func (s *PostureStore) load() (map[string]string, error) {
	v := map[string]string{}
	b, e := os.ReadFile(s.path)
	if os.IsNotExist(e) {
		return v, nil
	}
	if e != nil {
		return nil, e
	}
	e = json.Unmarshal(b, &v)
	return v, e
}
func (s *PostureStore) save(v map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(s.path, b, 0o600)
}
