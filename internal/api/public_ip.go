package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"time"
)

const publicIPSource = "api64.ipify.org"
const publicIPEndpoint = "https://api64.ipify.org?format=json"

// PublicIPResult is the public egress address observed by the external source.
// A failure is reported in Err so it never affects unrelated TRAZIP features.
type PublicIPResult struct {
	IP     string `json:"ip"`
	Family int    `json:"family"`
	Source string `json:"source"`
	Err    string `json:"err,omitempty"`
}

// PublicIP performs one bounded request to the public observation service.
// It does not include an analyzed target, capture, or any TRAZIP data.
func (s *Service) PublicIP() PublicIPResult {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return fetchPublicIP(ctx, publicIPEndpoint, http.DefaultClient)
}

func fetchPublicIP(ctx context.Context, endpoint string, client *http.Client) PublicIPResult {
	result := PublicIPResult{Source: publicIPSource}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		result.Err = fmt.Sprintf("public IP request: %v", err)
		return result
	}
	resp, err := client.Do(req)
	if err != nil {
		result.Err = fmt.Sprintf("public IP request: %v", err)
		return result
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		result.Err = fmt.Sprintf("public IP service returned HTTP %d", resp.StatusCode)
		return result
	}
	var payload struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		result.Err = fmt.Sprintf("public IP response: invalid JSON: %v", err)
		return result
	}
	addr, err := netip.ParseAddr(payload.IP)
	if err != nil {
		result.Err = "public IP response: invalid IP address"
		return result
	}
	result.IP = addr.String()
	if addr.Is4() {
		result.Family = 4
	} else {
		result.Family = 6
	}
	return result
}
