// Package geoupdate securely configures and updates MaxMind GeoLite2 datasets.
// It sends no capture or lookup data: network requests only authenticate to
// MaxMind and retrieve the City/ASN archives and their checksums.
package geoupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"

	"trazip/internal/intel/geoip"
	"trazip/internal/paths"
	"trazip/internal/securestore"
)

const (
	defaultBaseURL = "https://download.maxmind.com/geoip/databases"
	maxArchiveSize = 250 << 20
	maxMMDBSize    = 200 << 20
)

type config struct {
	AccountID        string    `json:"accountId"`
	EncryptedLicense string    `json:"encryptedLicenseKey"`
	AutoUpdate       bool      `json:"autoUpdate"`
	LastCheck        time.Time `json:"lastCheck,omitempty"`
	LastSuccess      time.Time `json:"lastSuccess,omitempty"`
	LastError        string    `json:"lastError,omitempty"`
}

// Status is safe to expose to the GUI: it never includes the license key.
type Status struct {
	AccountID     string              `json:"accountId"`
	HasLicenseKey bool                `json:"hasLicenseKey"`
	AutoUpdate    bool                `json:"autoUpdate"`
	Busy          bool                `json:"busy"`
	LastCheck     string              `json:"lastCheck,omitempty"`
	LastSuccess   string              `json:"lastSuccess,omitempty"`
	LastError     string              `json:"lastError,omitempty"`
	DataDir       string              `json:"dataDir"`
	Datasets      []geoip.DatasetInfo `json:"datasets"`
}

type Result struct {
	CheckedAt string   `json:"checkedAt"`
	Updated   []string `json:"updated"`
	Current   []string `json:"current"`
}

type Manager struct {
	mu         sync.Mutex
	busy       bool
	configPath string
	dataDir    string
	baseURL    string
	client     *http.Client
	geo        *geoip.Engine
}

func New(dataDir string, geo *geoip.Engine) *Manager {
	return &Manager{
		configPath: paths.Sub("geolite-updater.json"),
		dataDir:    dataDir,
		baseURL:    defaultBaseURL,
		client:     &http.Client{Timeout: 3 * time.Minute},
		geo:        geo,
	}
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, err := m.loadConfig()
	if err != nil {
		cfg.LastError = err.Error()
	}
	return m.status(cfg)
}

func (m *Manager) status(cfg config) Status {
	return Status{
		AccountID: cfg.AccountID, HasLicenseKey: cfg.EncryptedLicense != "",
		AutoUpdate: cfg.AutoUpdate, Busy: m.busy, LastCheck: formatTime(cfg.LastCheck),
		LastSuccess: formatTime(cfg.LastSuccess), LastError: cfg.LastError,
		DataDir: m.dataDir, Datasets: m.geo.Datasets(),
	}
}

// SaveSettings stores the license key encrypted for the current Windows user.
// An empty key preserves the existing credential.
func (m *Manager) SaveSettings(accountID, licenseKey string, autoUpdate bool) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.busy {
		return Status{}, fmt.Errorf("espera a que termine la actualización GeoLite2")
	}
	accountID = strings.TrimSpace(accountID)
	if _, err := strconv.ParseUint(accountID, 10, 64); accountID == "" || err != nil {
		return Status{}, fmt.Errorf("Account ID de MaxMind inválido")
	}
	cfg, err := m.loadConfig()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Status{}, err
	}
	if strings.TrimSpace(licenseKey) != "" {
		protected, err := securestore.Protect([]byte(strings.TrimSpace(licenseKey)))
		if err != nil {
			return Status{}, err
		}
		cfg.EncryptedLicense = base64.StdEncoding.EncodeToString(protected)
	}
	if cfg.EncryptedLicense == "" {
		return Status{}, fmt.Errorf("se requiere una License Key de MaxMind")
	}
	cfg.AccountID = accountID
	cfg.AutoUpdate = autoUpdate
	if err := m.saveConfig(cfg); err != nil {
		return Status{}, err
	}
	return m.status(cfg), nil
}

func (m *Manager) StartAuto(ctx context.Context) {
	go func() {
		m.autoCheck(ctx)
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.autoCheck(ctx)
			}
		}
	}()
}

func (m *Manager) autoCheck(ctx context.Context) {
	cfg, err := m.configSnapshot()
	if err != nil || !cfg.AutoUpdate || cfg.AccountID == "" || cfg.EncryptedLicense == "" {
		return
	}
	if !cfg.LastCheck.IsZero() && time.Since(cfg.LastCheck) < 24*time.Hour {
		return
	}
	_, _ = m.Check(ctx, false)
}

func (m *Manager) configSnapshot() (config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loadConfig()
}

func (m *Manager) Check(ctx context.Context, force bool) (Result, error) {
	m.mu.Lock()
	if m.busy {
		m.mu.Unlock()
		return Result{}, fmt.Errorf("ya hay una actualización GeoLite2 en curso")
	}
	m.busy = true
	cfg, err := m.loadConfig()
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.busy = false
		m.mu.Unlock()
	}()
	if err != nil {
		persistErr := m.finish(cfg, err, false)
		return Result{}, errors.Join(err, persistErr)
	}

	key, err := decryptLicense(cfg.EncryptedLicense)
	if err != nil {
		persistErr := m.finish(cfg, err, false)
		return Result{}, errors.Join(err, persistErr)
	}
	defer clear(key)
	if cfg.AccountID == "" || len(key) == 0 {
		err = fmt.Errorf("configura primero el Account ID y la License Key de MaxMind")
		persistErr := m.finish(cfg, err, false)
		return Result{}, errors.Join(err, persistErr)
	}

	result := Result{CheckedAt: formatTime(time.Now()), Updated: []string{}, Current: []string{}}
	for _, kind := range []string{"City", "ASN"} {
		updated, err := m.updateOne(ctx, cfg.AccountID, string(key), kind, force)
		if err != nil {
			persistErr := m.finish(cfg, err, false)
			return result, errors.Join(err, persistErr)
		}
		if updated {
			result.Updated = append(result.Updated, "GeoLite2 "+kind)
		} else {
			result.Current = append(result.Current, "GeoLite2 "+kind)
		}
	}
	if err := m.finish(cfg, nil, len(result.Updated) > 0); err != nil {
		return result, err
	}
	return result, nil
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format(time.RFC3339)
}

func (m *Manager) finish(cfg config, runErr error, success bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg.LastCheck = time.Now()
	if runErr != nil {
		cfg.LastError = runErr.Error()
	} else {
		cfg.LastError = ""
		if success {
			cfg.LastSuccess = cfg.LastCheck
		}
	}
	return m.saveConfig(cfg)
}

func decryptLicense(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}
	cipher, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("credencial cifrada inválida: %w", err)
	}
	return securestore.Unprotect(cipher)
}

func (m *Manager) updateOne(ctx context.Context, accountID, key, kind string, force bool) (bool, error) {
	edition := "GeoLite2-" + kind
	archiveURL := fmt.Sprintf("%s/%s/download?suffix=tar.gz", m.baseURL, edition)
	remoteTime, err := m.remoteModified(ctx, archiveURL, accountID, key)
	if err != nil {
		return false, fmt.Errorf("%s: %w", edition, err)
	}
	if !force && !remoteTime.IsZero() {
		for _, ds := range m.geo.Datasets() {
			if ds.Name == "GeoLite2 "+kind && ds.Present {
				if st, statErr := os.Stat(ds.Path); statErr == nil && !st.ModTime().Before(remoteTime) {
					return false, nil
				}
			}
		}
	}

	archive, err := m.download(ctx, archiveURL, accountID, key, maxArchiveSize)
	if err != nil {
		return false, fmt.Errorf("descarga %s: %w", edition, err)
	}
	checksumURL := fmt.Sprintf("%s/%s/download?suffix=tar.gz.sha256", m.baseURL, edition)
	checksum, err := m.download(ctx, checksumURL, accountID, key, 4096)
	if err != nil {
		return false, fmt.Errorf("checksum %s: %w", edition, err)
	}
	if err := verifySHA256(archive, checksum); err != nil {
		return false, fmt.Errorf("%s: %w", edition, err)
	}
	if err := os.MkdirAll(m.dataDir, 0o755); err != nil {
		return false, err
	}
	stage, err := extractMMDB(archive, m.dataDir, edition+".mmdb")
	if err != nil {
		return false, fmt.Errorf("extraer %s: %w", edition, err)
	}
	defer os.Remove(stage)
	reader, err := maxminddb.Open(stage)
	if err != nil {
		return false, fmt.Errorf("validar %s: %w", edition, err)
	}
	typeOK := reader.Metadata.DatabaseType == edition
	reader.Close()
	if !typeOK {
		return false, fmt.Errorf("tipo de base inesperado en %s", edition)
	}
	if err := m.geo.Install(kind, stage); err != nil {
		return false, err
	}
	return true, nil
}

func (m *Manager) remoteModified(ctx context.Context, url, accountID, key string) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return time.Time{}, err
	}
	req.SetBasicAuth(accountID, key)
	resp, err := m.client.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("MaxMind respondió HTTP %d", resp.StatusCode)
	}
	modified, _ := http.ParseTime(resp.Header.Get("Last-Modified"))
	return modified, nil
}

func (m *Manager) download(ctx context.Context, url, accountID, key string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(accountID, key)
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MaxMind respondió HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("respuesta excede el límite permitido")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("respuesta excede el límite permitido")
	}
	return data, nil
}

func verifySHA256(data, checksum []byte) error {
	fields := strings.Fields(string(checksum))
	if len(fields) == 0 || len(fields[0]) != sha256.Size*2 {
		return fmt.Errorf("formato SHA256 inválido")
	}
	want, err := hex.DecodeString(fields[0])
	if err != nil {
		return fmt.Errorf("SHA256 inválido")
	}
	got := sha256.Sum256(data)
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return fmt.Errorf("la verificación SHA256 falló")
	}
	return nil
}

func extractMMDB(archive []byte, dataDir, filename string) (string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return "", err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		if h.Typeflag != tar.TypeReg || filepath.Base(h.Name) != filename {
			continue
		}
		if h.Size <= 0 || h.Size > maxMMDBSize {
			return "", fmt.Errorf("tamaño MMDB inválido")
		}
		f, err := os.CreateTemp(dataDir, "."+filename+"-*.new")
		if err != nil {
			return "", err
		}
		path := f.Name()
		if err := f.Chmod(0o644); err == nil {
			_, err = io.CopyN(f, tr, h.Size)
		}
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			os.Remove(path)
			if err != nil {
				return "", err
			}
			return "", closeErr
		}
		return path, nil
	}
	return "", fmt.Errorf("el archivo %s no está en el paquete", filename)
}

func (m *Manager) loadConfig() (config, error) {
	var cfg config
	b, err := os.ReadFile(m.configPath)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("configuración GeoLite2 inválida: %w", err)
	}
	return cfg, nil
}

func (m *Manager) saveConfig(cfg config) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.configPath), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(m.configPath), ".geolite-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	backup := m.configPath + ".bak"
	_ = os.Remove(backup)
	hadOld := false
	if _, statErr := os.Stat(m.configPath); statErr == nil {
		if err := os.Rename(m.configPath, backup); err != nil {
			return err
		}
		hadOld = true
	}
	if err := os.Rename(name, m.configPath); err != nil {
		if hadOld {
			_ = os.Rename(backup, m.configPath)
		}
		return err
	}
	_ = os.Remove(backup)
	return nil
}
