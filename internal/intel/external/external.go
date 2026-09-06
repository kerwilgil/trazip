// Package external defines the disclosure envelope every query to a
// third-party service must carry (prompt maestro §5.7): source, query
// timestamp, data sent, cache policy, confidence and rate-limit notes.
// Shared by rdap, bgp and reputation so every external-source result looks
// the same to the GUI and nothing enriches silently.
package external

import "time"

// Disclosure documents one query to an external source. Every field is
// filled by the caller at query time — never left to the GUI to guess.
type Disclosure struct {
	Source      string `json:"source"`      // e.g. "RDAP (RIPE NCC)", "RIPEstat (RIPE NCC)"
	QueriedAt   string `json:"queriedAt"`   // RFC3339, built with external.Now()
	DataSent    string `json:"dataSent"`    // e.g. "dirección IP" — never more than what's needed
	CachePolicy string `json:"cachePolicy"` // e.g. "24h en memoria (bootstrap IANA)"
	Confidence  string `json:"confidence"`  // "alta" | "media" | "baja"
	RateLimit   string `json:"rateLimit"`   // free-text note on quotas/etiquette
}

// Now returns the current time formatted for Disclosure.QueriedAt, so every
// caller building a Disclosure uses the same wire format.
func Now() string { return time.Now().Format(time.RFC3339) }
