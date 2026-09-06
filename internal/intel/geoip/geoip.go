// Package geoip is TRAZIP's offline GeoIP/ASN engine (prompt maestro §5.4, §9
// Fase 1 #4/#6). It reads MaxMind GeoLite2 MMDB files from the data directory,
// caches lookups, and degrades cleanly when the datasets are absent — the rest
// of the app keeps working without them.
package geoip

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"

	"trazip/internal/paths"
)

// DatasetInfo records provenance of a loaded dataset (§5.4).
type DatasetInfo struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Type       string `json:"type,omitempty"`
	BuildEpoch uint   `json:"buildEpoch,omitempty"`
	Present    bool   `json:"present"`
}

// Result is the enrichment for one address (only populated fields are set).
type Result struct {
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"countryCode,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Lat         float64 `json:"lat,omitempty"`
	Lon         float64 `json:"lon,omitempty"`
	ASN         uint32  `json:"asn,omitempty"`
	Org         string  `json:"org,omitempty"`
	HasGeo      bool    `json:"hasGeo"`
	HasASN      bool    `json:"hasASN"`
}

type cityRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

type asnRecord struct {
	Number uint32 `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

const cacheMax = 8192

// Engine holds the open readers and an LRU-ish cache.
type Engine struct {
	mu       sync.RWMutex
	city     *maxminddb.Reader
	asn      *maxminddb.Reader
	cityInfo DatasetInfo
	asnInfo  DatasetInfo

	cache map[netip.Addr]Result
	order []netip.Addr
}

// Open loads whatever datasets exist under dataDir. It never fails: missing files
// simply leave the engine degraded.
func Open(dataDir string) *Engine {
	e := &Engine{cache: make(map[netip.Addr]Result)}

	cityPath := filepath.Join(dataDir, "GeoLite2-City.mmdb")
	if r, err := maxminddb.Open(cityPath); err == nil {
		e.city = r
		md := r.Metadata
		e.cityInfo = DatasetInfo{Name: "GeoLite2 City", Path: cityPath, Type: md.DatabaseType, BuildEpoch: md.BuildEpoch, Present: true}
	} else {
		e.cityInfo = DatasetInfo{Name: "GeoLite2 City", Path: cityPath}
	}

	asnPath := filepath.Join(dataDir, "GeoLite2-ASN.mmdb")
	if r, err := maxminddb.Open(asnPath); err == nil {
		e.asn = r
		md := r.Metadata
		e.asnInfo = DatasetInfo{Name: "GeoLite2 ASN", Path: asnPath, Type: md.DatabaseType, BuildEpoch: md.BuildEpoch, Present: true}
	} else {
		e.asnInfo = DatasetInfo{Name: "GeoLite2 ASN", Path: asnPath}
	}
	return e
}

// Available reports whether any dataset is loaded.
func (e *Engine) Available() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.city != nil || e.asn != nil
}

// Datasets returns provenance for the UI/reports.
func (e *Engine) Datasets() []DatasetInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return []DatasetInfo{e.cityInfo, e.asnInfo}
}

// Lookup enriches an address, using a cache. Returns a zero Result when no
// dataset is loaded or the address is not public.
func (e *Engine) Lookup(addr netip.Addr) Result {
	if !addr.IsValid() {
		return Result{}
	}
	addr = addr.Unmap()

	e.mu.RLock()
	if e.city == nil && e.asn == nil {
		e.mu.RUnlock()
		return Result{}
	}
	if r, ok := e.cache[addr]; ok {
		e.mu.RUnlock()
		return r
	}

	var res Result
	if e.city != nil {
		var rec cityRecord
		if err := e.city.Lookup(addr).Decode(&rec); err == nil {
			res.CountryCode = rec.Country.ISOCode
			res.Country = pickName(rec.Country.Names)
			res.City = pickName(rec.City.Names)
			if len(rec.Subdivisions) > 0 {
				res.Region = pickName(rec.Subdivisions[0].Names)
			}
			res.Lat = rec.Location.Latitude
			res.Lon = rec.Location.Longitude
			if res.Country != "" || res.City != "" {
				res.HasGeo = true
			}
		}
	}
	if e.asn != nil {
		var rec asnRecord
		if err := e.asn.Lookup(addr).Decode(&rec); err == nil && rec.Number != 0 {
			res.ASN = rec.Number
			res.Org = rec.Org
			res.HasASN = true
		}
	}
	e.mu.RUnlock()

	e.mu.Lock()
	if len(e.order) >= cacheMax {
		old := e.order[0]
		e.order = e.order[1:]
		delete(e.cache, old)
	}
	e.cache[addr] = res
	e.order = append(e.order, addr)
	e.mu.Unlock()

	return res
}

// Close releases the datasets.
func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.city != nil {
		e.city.Close()
		e.city = nil
	}
	if e.asn != nil {
		e.asn.Close()
		e.asn = nil
	}
}

// Install replaces one dataset with a validated staged MMDB. The staged file
// must live on the same volume as the destination so the final rename is
// atomic. Readers are swapped under the engine lock and the previous database
// is restored if any step fails.
func (e *Engine) Install(kind, stagedPath string) error {
	if kind != "City" && kind != "ASN" {
		return fmt.Errorf("dataset desconocido: %s", kind)
	}
	staged, err := maxminddb.Open(stagedPath)
	if err != nil {
		return fmt.Errorf("MMDB descargado inválido: %w", err)
	}
	expected := "GeoLite2-" + kind
	if staged.Metadata.DatabaseType != expected {
		staged.Close()
		return fmt.Errorf("tipo MMDB inesperado: %s", staged.Metadata.DatabaseType)
	}
	staged.Close()

	e.mu.Lock()
	defer e.mu.Unlock()

	var current **maxminddb.Reader
	var info *DatasetInfo
	if kind == "City" {
		current, info = &e.city, &e.cityInfo
	} else {
		current, info = &e.asn, &e.asnInfo
	}
	target := info.Path
	if target == "" {
		target = filepath.Join(filepath.Dir(stagedPath), expected+".mmdb")
	}
	backup := target + ".bak"

	if *current != nil {
		(*current).Close()
		*current = nil
	}
	reopen := func() error {
		restored, openErr := maxminddb.Open(target)
		if openErr != nil {
			return openErr
		}
		*current = restored
		md := restored.Metadata
		*info = DatasetInfo{Name: "GeoLite2 " + kind, Path: target, Type: md.DatabaseType, BuildEpoch: md.BuildEpoch, Present: true}
		return nil
	}
	_ = os.Remove(backup)
	hadOld := false
	if _, statErr := os.Stat(target); statErr == nil {
		if err := os.Rename(target, backup); err != nil {
			if reopenErr := reopen(); reopenErr != nil {
				return fmt.Errorf("no se pudo preparar el reemplazo: %w (reapertura falló: %v)", err, reopenErr)
			}
			return fmt.Errorf("no se pudo preparar el reemplazo: %w", err)
		}
		hadOld = true
	}
	rollback := func(cause error) error {
		_ = os.Remove(target)
		if hadOld {
			if renameErr := os.Rename(backup, target); renameErr != nil {
				return fmt.Errorf("%w (rollback falló: %v; copia anterior en %s)", cause, renameErr, backup)
			}
		}
		if hadOld {
			if reopenErr := reopen(); reopenErr != nil {
				return fmt.Errorf("%w (rollback no pudo reabrir la copia anterior: %v)", cause, reopenErr)
			}
		}
		return cause
	}
	if err := os.Rename(stagedPath, target); err != nil {
		return rollback(fmt.Errorf("no se pudo instalar el dataset: %w", err))
	}
	fresh, err := maxminddb.Open(target)
	if err != nil {
		return rollback(fmt.Errorf("no se pudo abrir el dataset instalado: %w", err))
	}
	*current = fresh
	md := fresh.Metadata
	*info = DatasetInfo{Name: "GeoLite2 " + kind, Path: target, Type: md.DatabaseType, BuildEpoch: md.BuildEpoch, Present: true}
	e.cache = make(map[netip.Addr]Result)
	e.order = nil
	_ = os.Remove(backup)
	return nil
}

// pickName prefers Spanish, then English, then any available name.
func pickName(names map[string]string) string {
	if names == nil {
		return ""
	}
	if v, ok := names["es"]; ok {
		return v
	}
	if v, ok := names["en"]; ok {
		return v
	}
	for _, v := range names {
		return v
	}
	return ""
}

// FindDataDir returns the canonical shared dataset directory. paths.Root
// resolves installed and portable mode, so production never falls back to a
// working-directory or executable-relative "data" folder.
func FindDataDir() string {
	return paths.DatasetDir()
}
