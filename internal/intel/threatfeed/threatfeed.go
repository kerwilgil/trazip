// Package threatfeed answers whether an address appears on a published list of
// networks known for abuse, using lists the operator downloads on purpose.
//
// It exists to fill the gap the reputation scorer documents about itself: its
// weights for tor/vpn/proxy already exist, but nothing was ever feeding them,
// so a clean score meant "nothing was checked" rather than "nothing was found".
//
// Two rules shape the design. Lists are downloaded only when asked and then
// consulted entirely offline, so scoring an address never tells anyone which
// address is being scored. And a hit is always reported with its source and
// what that source actually claims — "this range is on Spamhaus DROP" is a
// fact about a list, not a verdict about the traffic, and the difference
// matters when the answer is going into someone's incident report.
package threatfeed

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const storeFile = "threatfeed.json"

// storeVersion guards the on-disk shape; a bump discards an older store rather
// than misreading it.
const storeVersion = 1

// Category is what a list says about the addresses on it.
type Category string

const (
	// CatMalicious covers ranges a list asserts are controlled by or leased to
	// criminal operations.
	CatMalicious Category = "malicious"
	// CatTor covers Tor exit nodes: not abuse in itself, but traffic whose
	// origin is deliberately unattributable.
	CatTor Category = "tor"
)

// Hit is one list's claim about an address.
type Hit struct {
	Feed     string   `json:"feed"` // id de la fuente
	Name     string   `json:"name"` // nombre legible
	Category Category `json:"category"`
	Prefix   string   `json:"prefix,omitempty"` // el rango que coincidió
	Ref      string   `json:"ref,omitempty"`    // identificador en la fuente (p. ej. SBL)
	Detail   string   `json:"detail"`
	// FetchedAt is when this list was downloaded. A hit from a list six months
	// old is weaker evidence than a fresh one and the view has to be able to
	// say so.
	FetchedAt string `json:"fetchedAt,omitempty"`
}

// SourceInfo describes one downloaded list.
type SourceInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	FetchedAt   string `json:"fetchedAt,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	PrefixCount int    `json:"prefixCount"`
	Present     bool   `json:"present"`
	// AgeDays is derived on read so the view never has to parse dates.
	AgeDays int `json:"ageDays"`
}

// entry is one row on disk, kept short because these lists run to tens of
// thousands of rows.
type entry struct {
	P string   `json:"p"`           // prefijo CIDR
	C Category `json:"c"`           // categoría
	S string   `json:"s"`           // id de la fuente
	R string   `json:"r,omitempty"` // referencia en la fuente
}

type store struct {
	Version  int          `json:"version"`
	Prefixes []entry      `json:"prefixes"`
	Sources  []SourceInfo `json:"sources"`
}

type compiled struct {
	pfx  netip.Prefix
	e    entry
	bits int
}

// Engine holds the compiled lists.
type Engine struct {
	dataDir string

	storeMu sync.Mutex // serializes read-modify-write of the store file

	mu   sync.RWMutex
	v4   []compiled
	v6   []compiled
	srcs []SourceInfo
}

// New returns an Engine backed by dataDir, with whatever was downloaded
// previously already loaded — an absent or unreadable store just means no
// lists, which is the normal state before the operator downloads any.
func New(dataDir string) *Engine {
	e := &Engine{dataDir: dataDir}
	_ = e.Reload()
	return e
}

func (e *Engine) path() string { return filepath.Join(e.dataDir, storeFile) }

// Reload re-reads the store from disk and recompiles the prefixes.
func (e *Engine) Reload() error {
	s := e.load()

	var v4, v6 []compiled
	for _, en := range s.Prefixes {
		p, err := netip.ParsePrefix(en.P)
		if err != nil {
			continue // a corrupted row must not take the whole list down
		}
		c := compiled{pfx: p.Masked(), e: en, bits: p.Bits()}
		if p.Addr().Is4() {
			v4 = append(v4, c)
		} else {
			v6 = append(v6, c)
		}
	}
	// Most specific first, so a hit reports the tightest range that covers it.
	sortByBits(v4)
	sortByBits(v6)

	now := time.Now()
	srcs := make([]SourceInfo, 0, len(s.Sources))
	for _, si := range s.Sources {
		si.Present = si.PrefixCount > 0
		si.AgeDays = ageDays(si.FetchedAt, now)
		srcs = append(srcs, si)
	}
	sort.Slice(srcs, func(i, j int) bool { return srcs[i].ID < srcs[j].ID })

	e.mu.Lock()
	e.v4, e.v6, e.srcs = v4, v6, srcs
	e.mu.Unlock()
	return nil
}

func sortByBits(c []compiled) {
	sort.Slice(c, func(i, j int) bool { return c[i].bits > c[j].bits })
}

func ageDays(fetchedAt string, now time.Time) int {
	if fetchedAt == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, fetchedAt)
	if err != nil {
		return 0
	}
	d := int(now.Sub(t).Hours() / 24)
	if d < 0 {
		return 0
	}
	return d
}

// Sources lists every downloaded list, whether or not it currently holds rows.
func (e *Engine) Sources() []SourceInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()

	byID := make(map[string]SourceInfo, len(e.srcs))
	for _, s := range e.srcs {
		byID[s.ID] = s
	}
	out := make([]SourceInfo, 0, len(Catalog))
	for _, def := range Catalog {
		if s, ok := byID[def.ID]; ok {
			s.Name, s.URL = def.Name, def.URL
			out = append(out, s)
			continue
		}
		out = append(out, SourceInfo{ID: def.ID, Name: def.Name, URL: def.URL})
	}
	return out
}

// Loaded reports whether any list is available to consult.
func (e *Engine) Loaded() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.v4)+len(e.v6) > 0
}

// Lookup returns every list that covers addr, most specific prefix first.
// Multiple hits are returned rather than just the first: "on DROP and also a
// Tor exit" is a different situation from either one alone.
func (e *Engine) Lookup(addr netip.Addr) []Hit {
	hits := []Hit{}
	if !addr.IsValid() {
		return hits
	}
	addr = addr.Unmap()

	e.mu.RLock()
	defer e.mu.RUnlock()

	list := e.v4
	if addr.Is6() {
		list = e.v6
	}
	seen := make(map[string]bool, 2)
	for _, c := range list {
		if !c.pfx.Contains(addr) {
			continue
		}
		if seen[c.e.S] {
			continue // one hit per source: the tightest prefix already won
		}
		seen[c.e.S] = true
		hits = append(hits, e.hitFor(c))
	}
	return hits
}

func (e *Engine) hitFor(c compiled) Hit {
	h := Hit{
		Feed:     c.e.S,
		Category: c.e.C,
		Prefix:   c.pfx.String(),
		Ref:      c.e.R,
	}
	for _, def := range Catalog {
		if def.ID == c.e.S {
			h.Name, h.Detail = def.Name, def.Claim
			break
		}
	}
	for _, s := range e.srcs {
		if s.ID == c.e.S {
			h.FetchedAt = s.FetchedAt
			break
		}
	}
	return h
}

func (e *Engine) save(s store) error {
	if err := os.MkdirAll(e.dataDir, 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	// Written via a temp file and renamed so an interrupted save cannot leave
	// a half-written list behind.
	tmp := e.path() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, e.path())
}

func (e *Engine) load() store {
	var s store
	b, err := os.ReadFile(e.path())
	if err != nil {
		return store{Version: storeVersion}
	}
	if err := json.Unmarshal(b, &s); err != nil || s.Version != storeVersion {
		return store{Version: storeVersion}
	}
	return s
}

func nowRFC3339() string { return time.Now().Format(time.RFC3339) }
