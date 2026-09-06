// Package netclass answers "what kind of network is this address on?" —
// cloud, CDN, ISP, mobile, hosting — for the GeoIP Map legend and every other
// view that shows an endpoint.
//
// The honest constraint this package exists to respect: the free GeoLite2
// datasets TRAZIP already ships give the *operator* of an ASN (org name), not
// the *kind of service* running there. MaxMind sells that as separate products
// (GeoIP2-ISP, GeoIP2-Connection-Type). Rather than guess, this package
// prefers authoritative data — the prefix lists cloud and CDN providers
// publish about themselves — and falls back to a keyword heuristic over the
// org name only when no list covers the address, always saying which of the
// two produced the answer so the GUI never presents inference as fact.
package netclass

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// storeFile is the single normalized file all downloaded lists are folded
// into, so a lookup never has to parse five different vendor formats.
const storeFile = "netclass.json"

// storeVersion guards the on-disk shape; a bump makes older files ignored
// rather than misread.
const storeVersion = 1

// Category is the kind of network a prefix belongs to.
type Category string

const (
	Cloud      Category = "cloud"
	CDN        Category = "cdn"
	ISP        Category = "isp"
	Mobile     Category = "mobile"
	Hosting    Category = "hosting"
	Education  Category = "education"
	Enterprise Category = "enterprise"
)

// Match describes what is known about an address's network.
type Match struct {
	Category   string `json:"category"`
	Provider   string `json:"provider,omitempty"`
	Service    string `json:"service,omitempty"` // e.g. AWS EC2 / S3 / CLOUDFRONT
	Region     string `json:"region,omitempty"`
	Prefix     string `json:"prefix,omitempty"`
	Source     string `json:"source"`     // where the answer came from
	Confidence string `json:"confidence"` // alta | media | baja
	Evidence   string `json:"evidence"`   // what specifically matched
	Inferred   bool   `json:"inferred"`   // true when it is a guess, not a published fact
}

// SourceInfo records provenance for one downloaded list (§5.4: datasets are
// versioned with provider, hash and date, never silently refreshed).
type SourceInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	FetchedAt   string `json:"fetchedAt"`
	SHA256      string `json:"sha256"`
	PrefixCount int    `json:"prefixCount"`
	Present     bool   `json:"present"`
}

// entry is one prefix in the normalized store. Field names are short because
// this file holds tens of thousands of them.
type entry struct {
	P string `json:"p"`
	C string `json:"c"`
	R string `json:"pr,omitempty"`
	S string `json:"s,omitempty"`
	G string `json:"g,omitempty"`
}

type store struct {
	Version  int          `json:"version"`
	Sources  []SourceInfo `json:"sources"`
	Prefixes []entry      `json:"prefixes"`
}

// compiled is the lookup-ready form: prefixes parsed once and ordered by
// specificity so the first hit while scanning is the longest-prefix match.
type compiled struct {
	prefix netip.Prefix
	e      entry
}

// Engine holds the loaded lists. Safe for concurrent use; Reload swaps the
// data under a write lock so a download can't be observed half-applied.
type Engine struct {
	mu      sync.RWMutex
	storeMu sync.Mutex
	dataDir string
	v4      []compiled
	v6      []compiled
	sources []SourceInfo
}

// New returns an Engine reading from dataDir. A missing store is not an
// error: the engine degrades to the org-name heuristic, exactly like the
// GeoIP engine degrades when the .mmdb files aren't installed.
func New(dataDir string) *Engine {
	e := &Engine{dataDir: dataDir}
	_ = e.Reload()
	return e
}

// Reload re-reads the store from disk.
func (e *Engine) Reload() error {
	path := filepath.Join(e.dataDir, storeFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		e.mu.Lock()
		e.v4, e.v6, e.sources = nil, nil, nil
		e.mu.Unlock()
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var s store
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("%s ilegible: %w", storeFile, err)
	}
	if s.Version != storeVersion {
		return fmt.Errorf("%s tiene versión %d, se esperaba %d — volvé a descargar las listas", storeFile, s.Version, storeVersion)
	}

	var v4, v6 []compiled
	for _, en := range s.Prefixes {
		p, err := netip.ParsePrefix(en.P)
		if err != nil {
			continue // a malformed row must not poison the whole dataset
		}
		c := compiled{prefix: p.Masked(), e: en}
		if p.Addr().Is4() {
			v4 = append(v4, c)
		} else {
			v6 = append(v6, c)
		}
	}
	// Longest prefix first: scanning then stops at the most specific match.
	sortByBits(v4)
	sortByBits(v6)

	e.mu.Lock()
	e.v4, e.v6, e.sources = v4, v6, s.Sources
	e.mu.Unlock()
	return nil
}

func sortByBits(c []compiled) {
	sort.SliceStable(c, func(i, j int) bool {
		if c[i].prefix.Bits() != c[j].prefix.Bits() {
			return c[i].prefix.Bits() > c[j].prefix.Bits()
		}
		// Google Cloud's cloud.json and Google's broader goog.json can contain
		// the same prefix. The service-specific source must win regardless of
		// which list the operator downloaded first.
		return c[i].e.R == "Google Cloud" && c[j].e.R == "Google"
	})
}

// Sources reports what is installed, for Settings/Datasets.
func (e *Engine) Sources() []SourceInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]SourceInfo, 0, len(Catalog))
	byID := map[string]SourceInfo{}
	for _, s := range e.sources {
		byID[s.ID] = s
	}
	for _, def := range Catalog {
		if s, ok := byID[def.ID]; ok {
			s.Present = true
			out = append(out, s)
			continue
		}
		out = append(out, SourceInfo{ID: def.ID, Name: def.Name, URL: def.URL, Present: false})
	}
	return out
}

// Loaded reports whether any published list is installed.
func (e *Engine) Loaded() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.v4)+len(e.v6) > 0
}

// Lookup classifies addr. org is the ASN organisation name from GeoIP, used
// only for the heuristic fallback; pass "" if unknown. The second return is
// false when nothing at all could be said, which the GUI shows as no legend
// rather than as a category of "unknown".
func (e *Engine) Lookup(addr netip.Addr, org string) (Match, bool) {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return Match{}, false
	}

	e.mu.RLock()
	list := e.v4
	if !addr.Is4() {
		list = e.v6
	}
	for _, c := range list {
		if c.prefix.Contains(addr) {
			m := Match{
				Category:   c.e.C,
				Provider:   c.e.R,
				Service:    c.e.S,
				Region:     c.e.G,
				Prefix:     c.prefix.String(),
				Source:     "lista publicada por el proveedor",
				Confidence: "alta",
				Evidence:   fmt.Sprintf("%s figura en el rango %s que %s publica como propio", addr, c.prefix, c.e.R),
				Inferred:   false,
			}
			e.mu.RUnlock()
			return m, true
		}
	}
	e.mu.RUnlock()

	return heuristic(addr, org)
}

// orgKeyword maps a substring of an ASN organisation name to a category. This
// is deliberately conservative: it only covers patterns that are unambiguous
// in practice, because a wrong category is worse than no category — the whole
// point of the module is to avoid the "IPs get resold, the org isn't the
// operator" problem the published lists solve properly.
var orgKeyword = []struct {
	needle string
	cat    Category
	label  string
}{
	{"amazon", Cloud, "Amazon"},
	{"aws", Cloud, "Amazon AWS"},
	{"google", Cloud, "Google"},
	{"microsoft", Cloud, "Microsoft"},
	{"azure", Cloud, "Microsoft Azure"},
	{"oracle", Cloud, "Oracle Cloud"},
	{"alibaba", Cloud, "Alibaba Cloud"},
	{"digitalocean", Hosting, "DigitalOcean"},
	{"linode", Hosting, "Linode"},
	{"hetzner", Hosting, "Hetzner"},
	{"ovh", Hosting, "OVH"},
	{"vultr", Hosting, "Vultr"},
	{"hosting", Hosting, ""},
	{"datacenter", Hosting, ""},
	{"data center", Hosting, ""},
	{"cloudflare", CDN, "Cloudflare"},
	{"akamai", CDN, "Akamai"},
	{"fastly", CDN, "Fastly"},
	{"cdn", CDN, ""},
	{"telecom", ISP, ""},
	{"telecomunica", ISP, ""},
	{"cable", ISP, ""},
	{"broadband", ISP, ""},
	{"telefonica", ISP, "Telefónica"},
	{"claro", Mobile, "Claro"},
	{"movistar", Mobile, "Movistar"},
	{"digicel", Mobile, "Digicel"},
	{"tigo", Mobile, "Tigo"},
	{"wireless", Mobile, ""},
	{"mobile", Mobile, ""},
	{"universidad", Education, ""},
	{"university", Education, ""},
	{"universit", Education, ""},
	{"research", Education, ""},
}

// heuristic is the last-resort guess from the org name. Everything it returns
// is marked Inferred with medium/low confidence and carries the exact
// substring that triggered it, so the operator can judge it themselves.
func heuristic(addr netip.Addr, org string) (Match, bool) {
	o := strings.ToLower(strings.TrimSpace(org))
	if o == "" {
		return Match{}, false
	}
	for _, k := range orgKeyword {
		if !strings.Contains(o, k.needle) {
			continue
		}
		provider := k.label
		if provider == "" {
			provider = strings.TrimSpace(org)
		}
		conf := "media"
		if k.label == "" {
			// A generic word like "cable" or "hosting" is far weaker evidence
			// than a brand name.
			conf = "baja"
		}
		return Match{
			Category:   string(k.cat),
			Provider:   provider,
			Source:     "heurística por nombre de la organización",
			Confidence: conf,
			Evidence:   fmt.Sprintf("el nombre de la organización (%q) contiene %q", strings.TrimSpace(org), k.needle),
			Inferred:   true,
		}, true
	}
	return Match{}, false
}

// save writes the store atomically: a download interrupted halfway must not
// leave a truncated file that the next Reload would reject.
func (e *Engine) save(s store) error {
	if err := os.MkdirAll(e.dataDir, 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	final := filepath.Join(e.dataDir, storeFile)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// load reads the store without touching the in-memory index.
func (e *Engine) load() store {
	raw, err := os.ReadFile(filepath.Join(e.dataDir, storeFile))
	if err != nil {
		return store{Version: storeVersion}
	}
	var s store
	if err := json.Unmarshal(raw, &s); err != nil || s.Version != storeVersion {
		return store{Version: storeVersion}
	}
	return s
}

func nowRFC3339() string { return time.Now().Format(time.RFC3339) }
