package diagnosis

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"trazip/internal/intel/classify"
	"trazip/internal/model"
)

// runOwnership reports who announces/owns the address: offline GeoIP/ASN/
// NetClass first (available even in ModeOffline, exactly like the master
// plan's Offline stage list), then RDAP on demand for Standard/Full — never
// a live query in Offline mode (prompt maestro §5.7).
func runOwnership(ctx context.Context, deps Dependencies, haveIP bool, ip netip.Addr, mode Mode) DiagnosticStage {
	start := time.Now()
	s := DiagnosticStage{ID: StageIDOwnership, Label: "Propiedad"}

	if !haveIP {
		s.Status = StageSkipped
		s.Summary = "Sin dirección IP resuelta; no hay propietario que consultar."
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}
	s.Subjects = []string{ip.String()}
	if !classify.IsPublic(ip) {
		s.Status = StageUnknown
		s.Summary = "Dirección no pública; no aplica GeoIP/ASN/RDAP."
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}

	found := false
	if deps.Geo != nil {
		g := deps.Geo.Lookup(ip)
		if g.HasASN {
			found = true
			s.Evidence = append(s.Evidence, model.Evidence{
				Type: "asn_org", Value: fmt.Sprintf("AS%d %s", g.ASN, g.Org), Source: "diagnosis",
				Provenance: model.ProvResolved, Confidence: 80, Timestamp: time.Now(),
				Explain: "Organización del sistema autónomo, resuelta con el dataset GeoIP/ASN local.",
			})
		}
		if g.HasGeo {
			found = true
			s.Evidence = append(s.Evidence, model.Evidence{
				Type: "geoip_country", Value: g.Country, Source: "diagnosis",
				Provenance: model.ProvResolved, Confidence: 70, Timestamp: time.Now(),
				Explain: "País aproximado según el dataset GeoIP local — nunca una ubicación exacta.",
			})
		}
	}
	if deps.NetClass != nil {
		if m, ok := deps.NetClass.Lookup(ip, ""); ok {
			found = true
			s.Evidence = append(s.Evidence, model.Evidence{
				Type: "netclass", Value: m.Category, Source: "diagnosis",
				Provenance: model.ProvResolved, Confidence: 70, Timestamp: time.Now(),
				Explain: m.Evidence,
			})
		}
	}

	if mode != ModeOffline && deps.RDAP != nil {
		s.NetworkOut = true
		s.NetworkActions = append(s.NetworkActions, netAction(StageIDOwnership, "rdap", ip.String(), DestRIR, "IP pública"))
		rctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		res, err := deps.RDAP.LookupIP(rctx, ip.String())
		if err == nil && res.Err == "" {
			found = true
			s.Evidence = append(s.Evidence, model.Evidence{
				Type: "rdap", Value: res.Name, Source: "diagnosis",
				Provenance: model.ProvExternal, Confidence: 85, Timestamp: time.Now(),
				Explain: fmt.Sprintf("Registro RDAP en %s: %s (%s).", res.RIR, res.Name, res.CIDR),
			})
			// RDAP resolved the actual netblock this address belongs to —
			// a more precise subject than the single IP alone, so it's
			// added rather than replacing it.
			if res.CIDR != "" {
				s.Subjects = append(s.Subjects, res.CIDR)
			}
		}
	} else if mode == ModeOffline {
		s.Limitations = append(s.Limitations, "Modo offline: no se consultó RDAP; solo GeoIP/ASN/NetClass locales.")
	}

	if found {
		s.Status = StageOK
		s.Summary = "Propietario/ASN identificado."
	} else {
		s.Status = StageUnknown
		s.Summary = "No se pudo identificar propietario/ASN con los datos disponibles."
	}
	s.DurationMs = time.Since(start).Milliseconds()
	return s
}
