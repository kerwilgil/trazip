package lan

import "strings"

// ouiVendors is a small, high-confidence set of IEEE OUI prefixes (first 3 MAC
// bytes). Full coverage will come from a versioned data/oui.csv via the dataset
// manager; this covers common home/lab devices as a fallback.
var ouiVendors = map[string]string{
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
	"001B63": "Apple",
	"F0DBF8": "Apple",
	"A85C2C": "Apple",
	"00000C": "Cisco",
	"000D3A": "Microsoft",
	"00155D": "Microsoft (Hyper-V)",
	"001A11": "Google",
	"3C5AB4": "Google",
	"F4F5D8": "Google",
}

// Vendor resolves a MAC prefix to a vendor label, or "" if unknown.
func Vendor(mac string) string {
	clean := strings.ToUpper(mac)
	clean = strings.ReplaceAll(clean, ":", "")
	clean = strings.ReplaceAll(clean, "-", "")
	if len(clean) < 6 {
		return ""
	}
	return ouiVendors[clean[:6]]
}
