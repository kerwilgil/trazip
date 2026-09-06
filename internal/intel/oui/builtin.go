package oui

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// builtin is a small, high-confidence set of 24-bit OUI prefixes covering
// common home and lab hardware. It exists so MAC vendor resolution still says
// something useful before anyone downloads the IEEE registries — the same
// "degrade, don't disappear" rule the GeoIP engine follows when its .mmdb
// files are absent. Lookups consult it last, so a downloaded registry always
// wins.
var builtin = map[string]string{
	"B827EB": "Raspberry Pi",
	"DCA632": "Raspberry Pi",
	"E45F01": "Raspberry Pi",
	"2CCF67": "Raspberry Pi",
	"240AC4": "Espressif (ESP32)",
	"3C71BF": "Espressif (ESP32)",
	"8CAAB5": "Espressif (ESP32)",
	"5CCF7F": "Espressif (ESP8266)",
	"50C7BF": "TP-Link",
	"1C61B4": "TP-Link",
	"002722": "Ubiquiti",
	"FCECDA": "Ubiquiti",
	"744D28": "MikroTik",
	"4C5E0C": "MikroTik",
	"6C3B6B": "MikroTik",
	"48A98A": "MikroTik",
	"E48D8C": "MikroTik",
	"000C42": "MikroTik",
	"001CF0": "D-Link",
	"3C1E04": "D-Link",
	"F81A67": "TP-Link",
	"A0F3C1": "TP-Link",
	"001A2B": "Cisco",
	"00000C": "Cisco",
}

// save writes the store atomically: an interrupted write must not leave a
// truncated file that the next Reload would reject.
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

func removeFile(dataDir string) error {
	err := os.Remove(filepath.Join(dataDir, storeFile))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
