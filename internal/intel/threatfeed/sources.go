package threatfeed

import (
	"bufio"
	"bytes"
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

// maxDownload bounds any single list. DROP is around 100 KB and the Tor exit
// list around 20 KB; 32 MB is generous headroom while still refusing to stream
// an unbounded response into memory.
const maxDownload = 32 << 20

// SourceDef describes one downloadable list.
type SourceDef struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	URL  string   `json:"url"`
	Cat  Category `json:"category"`
	// Claim is what a hit on this list actually means. It is shown with every
	// hit because "appears on a list" is worthless to whoever reads the report
	// unless they know what the list asserts.
	Claim string `json:"claim"`
	Note  string `json:"note,omitempty"`
}

// Catalog is every list TRAZIP knows how to fetch. Both were verified live
// before being added — the same rule netclass follows about never pinning a
// URL that has not been confirmed to serve what it claims.
//
// abuse.ch's Feodo Tracker was evaluated and deliberately left out: its IP
// blocklist currently serves five entries and had not been updated in five
// months. A source that thin does not add coverage, it adds a false sense of
// having checked something.
var Catalog = []SourceDef{
	{
		ID: "spamhaus-drop", Name: "Spamhaus DROP", Cat: CatMalicious,
		URL:   "https://www.spamhaus.org/drop/drop_v4.json",
		Claim: "rango que Spamhaus considera controlado o arrendado por operaciones delictivas; su recomendación es no cursar tráfico con él",
		Note:  "incluye el identificador SBL de cada registro para consultarlo en la fuente",
	},
	{
		ID: "tor-exit", Name: "Nodos de salida Tor", Cat: CatTor,
		URL:   "https://check.torproject.org/torbulkexitlist",
		Claim: "nodo de salida de Tor: el origen real del tráfico es deliberadamente inatribuible, lo que no lo hace malicioso por sí solo",
	},
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
// that source contributed before and leaving the others untouched.
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
	entries, err := parseSource(def, body)
	if err != nil {
		return SourceInfo{}, fmt.Errorf("%s: %w", def.Name, err)
	}
	if len(entries) == 0 {
		// Refusing an empty result protects against the failure mode where a
		// source starts requiring an API key and answers 200 with a header-only
		// body: silently replacing a good list with nothing would turn every
		// address clean without telling anyone.
		return SourceInfo{}, fmt.Errorf("%s no devolvió ningún rango — se conserva la lista anterior", def.Name)
	}

	s := e.load()
	kept := s.Prefixes[:0]
	for _, en := range s.Prefixes {
		if en.S != "" && en.S != def.ID {
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

// Remove deletes one source's rows from the store.
func (e *Engine) Remove(id string) error {
	e.storeMu.Lock()
	defer e.storeMu.Unlock()

	s := e.load()
	kept := s.Prefixes[:0]
	for _, en := range s.Prefixes {
		if en.S != id {
			kept = append(kept, en)
		}
	}
	s.Prefixes = kept

	srcs := s.Sources[:0]
	for _, si := range s.Sources {
		if si.ID != id {
			srcs = append(srcs, si)
		}
	}
	s.Sources = srcs
	s.Version = storeVersion

	if err := e.save(s); err != nil {
		return err
	}
	return e.Reload()
}

func fetch(ctx context.Context, url string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("no se pudo descargar %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("%s respondió HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload))
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(body)
	return body, hex.EncodeToString(sum[:]), nil
}

func parseSource(def SourceDef, body []byte) ([]entry, error) {
	switch def.ID {
	case "spamhaus-drop":
		return parseDROP(body)
	case "tor-exit":
		return parseAddressList(body, def), nil
	default:
		return nil, fmt.Errorf("no hay analizador para %q", def.ID)
	}
}

// parseDROP reads Spamhaus's JSON Lines format: one object per line, plus a
// trailing metadata line that has no "cidr" and is skipped.
func parseDROP(body []byte) ([]entry, error) {
	var out []entry
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var row struct {
			CIDR  string `json:"cidr"`
			SBLID string `json:"sblid"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			continue
		}
		if !validPrefix(row.CIDR) {
			continue
		}
		out = append(out, entry{P: row.CIDR, C: CatMalicious, S: "spamhaus-drop", R: row.SBLID})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// parseAddressList reads a plain list of one address (or CIDR) per line, with
// "#" and ";" comments — the shape the Tor exit list uses.
func parseAddressList(body []byte, def SourceDef) []entry {
	var out []entry
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if i := strings.IndexAny(line, " \t;#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if strings.Contains(line, "/") {
			if validPrefix(line) {
				out = append(out, entry{P: line, C: def.Cat, S: def.ID})
			}
			continue
		}
		// A bare address becomes a host prefix so lookup stays uniform.
		addr, err := netip.ParseAddr(line)
		if err != nil {
			continue
		}
		out = append(out, entry{P: netip.PrefixFrom(addr, addr.BitLen()).String(), C: def.Cat, S: def.ID})
	}
	return out
}

func validPrefix(s string) bool {
	p, err := netip.ParsePrefix(s)
	return err == nil && p.Addr().IsValid()
}
