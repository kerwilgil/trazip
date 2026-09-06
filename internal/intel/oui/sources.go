package oui

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const sourceLabel = "IEEE Registration Authority (registros oficiales MA-L, MA-M y MA-S)"

// maxDownload bounds each registry. oui.csv is the largest at roughly 4 MB
// including postal addresses; 32 MB is generous headroom.
const maxDownload = 32 << 20

// registries are the three IEEE files that together cover every assignment
// size. They are fetched from IEEE directly rather than from an aggregator:
// the URLs are stable (an aggregator this project looked at serves its
// download behind a rotating hash), the data is the authoritative original,
// and there is no third-party licence to interpret.
var registries = []struct {
	Name string
	URL  string
	// Hex digits in this registry's prefixes: 6 = 24 bits, 7 = 28, 9 = 36.
	Digits int
}{
	{"MA-L", "https://standards-oui.ieee.org/oui/oui.csv", 6},
	{"MA-M", "https://standards-oui.ieee.org/oui28/mam.csv", 7},
	{"MA-S", "https://standards-oui.ieee.org/oui36/oui36.csv", 9},
}

var httpClient = &http.Client{
	Timeout: 3 * time.Minute,
	Transport: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 15 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
	},
}

// Update downloads the three IEEE registries and replaces the local store.
// All three are fetched before anything is written, so a failure halfway
// leaves the previous data intact rather than a half-updated registry.
func (e *Engine) Update(ctx context.Context) (Info, error) {
	merged := make(map[string]string, 56000)
	var loaded []string

	for _, r := range registries {
		rows, err := fetchRegistry(ctx, r.URL, r.Digits)
		if err != nil {
			return Info{}, fmt.Errorf("%s: %w", r.Name, err)
		}
		if len(rows) == 0 {
			return Info{}, fmt.Errorf("%s no devolvió ninguna asignación — se conserva la lista anterior", r.Name)
		}
		for k, v := range rows {
			merged[k] = v
		}
		loaded = append(loaded, r.Name)
	}

	s := store{
		Version:    storeVersion,
		FetchedAt:  time.Now().Format(time.RFC3339),
		Registries: strings.Join(loaded, ", "),
		Prefixes:   merged,
	}
	if err := e.save(s); err != nil {
		return Info{}, err
	}
	if err := e.Reload(); err != nil {
		return Info{}, err
	}
	return e.Info(), nil
}

// Remove deletes the downloaded registry, falling back to the built-in table.
func (e *Engine) Remove() error {
	if err := removeFile(e.dataDir); err != nil {
		return err
	}
	return e.Reload()
}

// fetchRegistry parses one IEEE CSV. The format is
// Registry,Assignment,Organization Name,Organization Address — only the first
// three matter, and the postal address is dropped on purpose: it triples the
// stored size and answers a question nobody asks of a network tool.
func fetchRegistry(ctx context.Context, url string, digits int) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "TRAZIP/oui")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("no se pudo descargar: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("respondió %s", resp.Status)
	}

	cr := csv.NewReader(io.LimitReader(resp.Body, maxDownload))
	cr.FieldsPerRecord = -1 // addresses contain stray quoting; tolerate it
	cr.LazyQuotes = true

	out := make(map[string]string, 40000)
	first := true
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// One malformed row must not discard the other forty thousand.
			continue
		}
		if first {
			first = false
			continue // header
		}
		if len(rec) < 3 {
			continue
		}
		prefix := normalize(rec[1])
		name := strings.TrimSpace(rec[2])
		if len(prefix) != digits || name == "" {
			continue
		}
		out[prefix] = name
	}
	return out, nil
}
