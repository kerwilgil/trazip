package netclass

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// maxDownload bounds any single list. AWS's is the largest at roughly 3 MB;
// 32 MB leaves generous headroom while still refusing to stream an unbounded
// response into memory.
const maxDownload = 32 << 20

// SourceDef describes one downloadable list.
type SourceDef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
	Note string `json:"note,omitempty"`
}

// Catalog is every list TRAZIP knows how to fetch. Each URL is the vendor's
// own published endpoint — the provider describing its own address space,
// which is why a hit counts as fact rather than inference.
//
// Azure is deliberately absent: Microsoft publishes its Service Tags behind a
// download page whose file URL rotates weekly, with no stable direct link to
// pin, and guessing at a rotating URL is exactly the kind of unverifiable
// endpoint this project refuses to fabricate.
var Catalog = []SourceDef{
	{ID: "aws", Name: "Amazon Web Services", URL: "https://ip-ranges.amazonaws.com/ip-ranges.json", Note: "incluye servicio (EC2, S3, CLOUDFRONT) y región"},
	{ID: "cloudflare", Name: "Cloudflare", URL: "https://www.cloudflare.com/ips-v4"},
	{ID: "cloudflare6", Name: "Cloudflare (IPv6)", URL: "https://www.cloudflare.com/ips-v6"},
	{ID: "gcp", Name: "Google Cloud", URL: "https://www.gstatic.com/ipranges/cloud.json", Note: "incluye región"},
	{ID: "google", Name: "Google (global)", URL: "https://www.gstatic.com/ipranges/goog.json"},
	{ID: "fastly", Name: "Fastly", URL: "https://api.fastly.com/public-ip-list"},
}

// FindSource returns the catalog entry for id.
func FindSource(id string) (SourceDef, bool) {
	for _, s := range Catalog {
		if s.ID == id {
			return s, true
		}
	}
	return SourceDef{}, false
}

// httpClient is deliberately local and short-lived: these are the only
// outbound requests this package ever makes, and only when the operator
// clicks Download.
var httpClient = &http.Client{
	Timeout: 60 * time.Second,
	Transport: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 15 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
	},
}

// Update downloads one list and folds it into the store, replacing whatever
// that source contributed before. Other sources are left untouched, so
// refreshing AWS never silently drops Cloudflare.
func (e *Engine) Update(ctx context.Context, id string) (SourceInfo, error) {
	e.storeMu.Lock()
	defer e.storeMu.Unlock()

	def, ok := FindSource(id)
	if !ok {
		return SourceInfo{}, fmt.Errorf("fuente desconocida: %q", id)
	}

	body, sum, err := fetch(ctx, def.URL)
	if err != nil {
		return SourceInfo{}, err
	}
	entries, err := parseSource(def.ID, body)
	if err != nil {
		return SourceInfo{}, fmt.Errorf("%s: %w", def.Name, err)
	}
	if len(entries) == 0 {
		return SourceInfo{}, fmt.Errorf("%s no devolvió ningún prefijo — se conserva la lista anterior", def.Name)
	}

	s := e.load()
	// Drop this source's previous rows, keep everyone else's.
	kept := s.Prefixes[:0]
	for _, en := range s.Prefixes {
		if en.C != "" && sourceOf(en) != def.ID {
			kept = append(kept, en)
		}
	}
	s.Prefixes = append(kept, entries...)

	info := SourceInfo{
		ID: def.ID, Name: def.Name, URL: def.URL,
		FetchedAt: nowRFC3339(), SHA256: sum, PrefixCount: len(entries), Present: true,
	}
	replaced := false
	for i, existing := range s.Sources {
		if existing.ID == def.ID {
			s.Sources[i] = info
			replaced = true
			break
		}
	}
	if !replaced {
		s.Sources = append(s.Sources, info)
	}
	s.Version = storeVersion

	if err := e.save(s); err != nil {
		return SourceInfo{}, err
	}
	if err := e.Reload(); err != nil {
		return SourceInfo{}, err
	}
	return info, nil
}

// Remove deletes one source's prefixes from the store.
func (e *Engine) Remove(id string) error {
	e.storeMu.Lock()
	defer e.storeMu.Unlock()

	s := e.load()
	kept := s.Prefixes[:0]
	for _, en := range s.Prefixes {
		if sourceOf(en) != id {
			kept = append(kept, en)
		}
	}
	s.Prefixes = kept
	var srcs []SourceInfo
	for _, src := range s.Sources {
		if src.ID != id {
			srcs = append(srcs, src)
		}
	}
	s.Sources = srcs
	s.Version = storeVersion
	if err := e.save(s); err != nil {
		return err
	}
	return e.Reload()
}

// sourceOf recovers which catalog source produced an entry. The store keeps
// it in the provider field prefix-free, so this maps back by provider name.
func sourceOf(en entry) string {
	switch en.R {
	case "Amazon AWS":
		return "aws"
	case "Cloudflare":
		if strings.Contains(en.P, ":") {
			return "cloudflare6"
		}
		return "cloudflare"
	case "Google Cloud":
		return "gcp"
	case "Google":
		return "google"
	case "Fastly":
		return "fastly"
	}
	return ""
}

func fetch(ctx context.Context, url string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "TRAZIP/netclass")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("no se pudo descargar %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("%s respondió %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return nil, "", err
	}
	if len(body) > maxDownload {
		return nil, "", fmt.Errorf("%s excede el límite de %d MB", url, maxDownload>>20)
	}
	sum := sha256.Sum256(body)
	return body, hex.EncodeToString(sum[:]), nil
}

// parseSource turns a vendor payload into normalized entries.
func parseSource(id string, body []byte) ([]entry, error) {
	switch id {
	case "aws":
		return parseAWS(body)
	case "cloudflare", "cloudflare6":
		return parsePlainList(body, string(CDN), "Cloudflare"), nil
	case "gcp":
		return parseGoogle(body, string(Cloud), "Google Cloud")
	case "google":
		// goog.json proves Google ownership, not that every address is a
		// customer Google Cloud workload. Keep that distinction explicit.
		return parseGoogle(body, string(Enterprise), "Google")
	case "fastly":
		return parseFastly(body)
	}
	return nil, fmt.Errorf("sin parser para %q", id)
}

func parseAWS(body []byte) ([]entry, error) {
	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Region   string `json:"region"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Region     string `json:"region"`
			Service    string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("JSON inesperado: %w", err)
	}
	type awsPrefix struct {
		p, region, service string
	}
	rows := make([]awsPrefix, 0, len(doc.Prefixes)+len(doc.IPv6Prefixes))
	for _, p := range doc.Prefixes {
		rows = append(rows, awsPrefix{p: p.IPPrefix, region: p.Region, service: p.Service})
	}
	for _, p := range doc.IPv6Prefixes {
		rows = append(rows, awsPrefix{p: p.IPv6Prefix, region: p.Region, service: p.Service})
	}

	// AMAZON is AWS's catch-all service label. Many rows duplicate a more
	// specific service for the exact same prefix, but thousands of ranges are
	// AMAZON-only. Keep those unique ranges and discard only exact duplicates.
	specific := make(map[string]bool, len(rows))
	for _, row := range rows {
		if row.service != "AMAZON" && validPrefix(row.p) {
			specific[row.p] = true
		}
	}

	out := make([]entry, 0, len(rows))
	for _, row := range rows {
		p, region, service := row.p, row.region, row.service
		if !validPrefix(p) {
			continue
		}
		if service == "AMAZON" && specific[p] {
			continue
		}
		cat := Cloud
		if service == "CLOUDFRONT" {
			cat = CDN
		}
		out = append(out, entry{P: p, C: string(cat), R: "Amazon AWS", S: service, G: region})
	}
	return out, nil
}

func parseGoogle(body []byte, cat, provider string) ([]entry, error) {
	var doc struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			IPv6Prefix string `json:"ipv6Prefix"`
			Scope      string `json:"scope"`
			Service    string `json:"service"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("JSON inesperado: %w", err)
	}
	out := make([]entry, 0, len(doc.Prefixes))
	for _, p := range doc.Prefixes {
		for _, cidr := range []string{p.IPv4Prefix, p.IPv6Prefix} {
			if !validPrefix(cidr) {
				continue
			}
			out = append(out, entry{P: cidr, C: cat, R: provider, S: p.Service, G: p.Scope})
		}
	}
	return out, nil
}

func parseFastly(body []byte) ([]entry, error) {
	var doc struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("JSON inesperado: %w", err)
	}
	out := make([]entry, 0, len(doc.Addresses)+len(doc.IPv6Addresses))
	for _, cidr := range append(append([]string{}, doc.Addresses...), doc.IPv6Addresses...) {
		if !validPrefix(cidr) {
			continue
		}
		out = append(out, entry{P: cidr, C: string(CDN), R: "Fastly"})
	}
	return out, nil
}

// parsePlainList reads the one-CIDR-per-line format Cloudflare publishes.
func parsePlainList(body []byte, cat, provider string) []entry {
	var out []entry
	for _, line := range strings.Split(string(body), "\n") {
		cidr := strings.TrimSpace(line)
		if cidr == "" || strings.HasPrefix(cidr, "#") || !validPrefix(cidr) {
			continue
		}
		out = append(out, entry{P: cidr, C: cat, R: provider})
	}
	return out
}

func validPrefix(s string) bool {
	if s == "" {
		return false
	}
	_, err := netip.ParsePrefix(strings.TrimSpace(s))
	return err == nil
}
