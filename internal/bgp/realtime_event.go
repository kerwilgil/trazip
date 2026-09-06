// Realtime event normalization for v1.2 (BGP_INTELLIGENCE_ROADMAP.md §23.3).
// Pure decode: RIS Live wire bytes -> []BGPRealtimeEvent, no I/O, no
// network, no goroutines — testable entirely with recorded/synthetic
// fixtures. The WebSocket connection and session lifecycle live in
// realtime.go.
package bgp

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// PathElementKind distingue un salto ASN individual de un AS_SET (roadmap
// §23.3). Nunca aplanado.
type PathElementKind string

const (
	PathElementASN   PathElementKind = "asn"
	PathElementASSet PathElementKind = "as_set"
)

// PathElement es una posición en el AS path.
type PathElement struct {
	Kind PathElementKind
	ASN  int   `json:"asn,omitempty"`
	Set  []int `json:"set,omitempty"`
}

// BGPPath es el AS path completo, en orden — nunca []int plano.
type BGPPath []PathElement

// OriginResolution — ver BGP_INTELLIGENCE_ROADMAP.md §23.3 (v1.2 P1-1
// closure). Un AS_SET al final del path preserva agregación de ruta; eso
// NO prueba múltiples route origins reales, así que Determinate=false en
// ese caso, nunca aplanado a un ASN inventado.
type OriginResolution struct {
	Determinate bool
	ASN         int
	Reason      string
}

// BGPRealtimeEventType — fuente vs. derivado (roadmap §23.3).
type BGPRealtimeEventType string

const (
	EventAnnouncement BGPRealtimeEventType = "announcement"
	EventWithdrawal   BGPRealtimeEventType = "withdrawal"

	// Derived events. Gate 2 implementó únicamente los comparadores puros
	// OriginChanged/PathChanged (abajo). Gate 3 los conecta a estado
	// previo trackeado por (peer, prefix) a lo largo de una sesión viva —
	// bounded por la propia sesión (nunca un mapa global) — y añade
	// moas_appeared/moas_disappeared (agregación cross-peer de orígenes
	// determinables) y rpki_transition (llamadas reales a
	// RPKIValidateDetailed, nunca sobre miembros de AS_SET). Ver
	// realtime_derive.go para la lógica con estado; este archivo se
	// mantiene I/O-free (ver doc del package arriba).
	EventPathChanged     BGPRealtimeEventType = "path_changed"
	EventOriginChanged   BGPRealtimeEventType = "origin_changed"
	EventMOASAppeared    BGPRealtimeEventType = "moas_appeared"
	EventMOASDisappeared BGPRealtimeEventType = "moas_disappeared"
	EventRPKITransition  BGPRealtimeEventType = "rpki_transition"
)

// BGPRealtimeEvent — ver roadmap §23.3 para el contrato completo.
type BGPRealtimeEvent struct {
	ID              string
	SourceMessageID string
	Timestamp       string
	Type            BGPRealtimeEventType
	Resource        string
	Prefix          string
	PeerASN         int
	Peer            string
	Path            BGPPath
	Origin          OriginResolution
	Previous        *BGPRealtimeChangeSnapshot
	Current         *BGPRealtimeChangeSnapshot
	Source          string // "ris-live" | "derived"
	Evidence        []ComponentEvidence
}

// BGPRealtimeChangeSnapshot — estado previo/actual comparado por un
// derived event.
type BGPRealtimeChangeSnapshot struct {
	Path      BGPPath
	Origin    OriginResolution
	RPKIState string
	// SourceEventID is the BGPRealtimeEvent.ID of the source event that
	// established THIS snapshot (v1.2 Gate 3 P1-3 closure) — lets a
	// derived event's Evidence honestly reference exactly which source
	// observations it was computed from, instead of leaving Evidence
	// empty while asserting a change. Empty for a snapshot that never had
	// an originating source event (there is none for the derivedState
	// zero value).
	SourceEventID string
}

// --- RIS Live wire shapes (unexported — internal decode only) ---

type risMessage struct {
	Type string          `json:"type"` // "ris_message" | "ris_error" | "KEEPALIVE"
	Data json.RawMessage `json:"data,omitempty"`
}

type risUpdateData struct {
	Timestamp     float64           `json:"timestamp"`
	Peer          string            `json:"peer"`
	PeerASN       string            `json:"peer_asn"` // string en el wire (§23.1) — nunca asumido int
	ID            string            `json:"id"`
	Host          string            `json:"host"`
	Type          string            `json:"type"` // "UPDATE" | "OPEN" | "NOTIFICATION" | "RIS_PEER_STATE"
	Path          []json.RawMessage `json:"path"`
	Origin        string            `json:"origin"` // atributo BGP ORIGIN (IGP/EGP/INCOMPLETE) — wire real en mayúsculas ("IGP"), manual en minúsculas; comparar case-insensitive (§23.1). Distinto del concepto "route origin ASN" (OriginResolution arriba).
	Announcements []risAnnouncement `json:"announcements"`
	Withdrawals   []string          `json:"withdrawals"`
}

type risAnnouncement struct {
	NextHop  string   `json:"next_hop"`
	Prefixes []string `json:"prefixes"`
}

// RISFrameError representa un frame de protocolo "ris_error" real de RIS
// Live — distinto de JSON malformado o de un ris_message con campos
// inválidos. Nunca se ignora silenciosamente: el session core
// (realtime.go) lo trata como un error observable y termina la sesión en
// FAILED (v1.2 P1-3 / RIS_ERROR closure, política conservadora de Gate 2 —
// ver readLoop).
type RISFrameError struct {
	Message string
}

func (e *RISFrameError) Error() string {
	if e.Message == "" {
		return "RIS Live ris_error (sin mensaje)"
	}
	return "RIS Live ris_error: " + e.Message
}

// DecodeRISMessage decodifica un frame crudo del WebSocket de RIS Live.
// Solo los frames {"type":"ris_message","data":{...,"type":"UPDATE",...}}
// producen BGPRealtimeEvent(s). "KEEPALIVE" y sub-tipos distintos de
// UPDATE (OPEN/NOTIFICATION/RIS_PEER_STATE) son frames de protocolo
// válidos que producen cero eventos, nunca un error. "ris_error" es un
// frame de protocolo real y distinto — nunca confundido con JSON
// malformado (v1.2 P1-3 closure) — devuelve un *RISFrameError explícito
// para que el session core lo trate como error observable, nunca
// silenciado. JSON malformado, o un ris_message.data con campos de wire
// que impiden construir un evento honesto (peer_asn/timestamp
// obligatorios ausentes/inválidos, id vacío), también devuelve un error
// explícito y cero eventos — nunca panic, nunca un evento fabricado.
func DecodeRISMessage(resource string, raw []byte) ([]BGPRealtimeEvent, error) {
	var msg risMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, fmt.Errorf("frame RIS Live no interpretable: %w", err)
	}
	switch msg.Type {
	case "ris_error":
		var errData struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(msg.Data, &errData) // best-effort: un ris_error sin campo message reconocible sigue siendo un ris_error observable
		return nil, &RISFrameError{Message: errData.Message}
	case "KEEPALIVE":
		return nil, nil
	case "ris_message":
		// sigue abajo
	default:
		return nil, nil
	}
	var upd risUpdateData
	if err := json.Unmarshal(msg.Data, &upd); err != nil {
		return nil, fmt.Errorf("ris_message.data no interpretable: %w", err)
	}
	if !strings.EqualFold(upd.Type, "UPDATE") {
		return nil, nil
	}
	return normalizeUpdateEvents(resource, upd)
}

// normalizeUpdateEvents valida los campos de wire compartidos por TODOS
// los eventos que este mensaje produciría (id/peer_asn) antes de construir
// ninguno — un id vacío o un peer_asn inválido invalidan el mensaje
// completo, porque ambos son campos por-mensaje que de otro modo se
// fabricarían idénticos (y falsos) en cada evento derivado (v1.2 P1-3
// closure, casos B y D). El timestamp, en cambio, se representa como ""
// cuando es inválido/ausente/no finito en vez de rechazar el mensaje —
// nunca fabricado como epoch 1970 (caso C), pero tampoco descarta eventos
// por lo demás honestos. La validez de cada prefix es por-item (caso E):
// un prefix vacío/inválido descarta SOLO ese announcement/withdrawal,
// nunca el mensaje entero.
func normalizeUpdateEvents(resource string, upd risUpdateData) ([]BGPRealtimeEvent, error) {
	if strings.TrimSpace(upd.ID) == "" {
		return nil, fmt.Errorf("id de mensaje RIS Live vacío — no se puede derivar un Event ID/SourceMessageID honesto")
	}
	peerASN, ok := parsePeerASN(upd.PeerASN)
	if !ok {
		return nil, fmt.Errorf("peer_asn inválido en el wire: %q", upd.PeerASN)
	}
	ts := risTimestampToRFC3339(upd.Timestamp)

	path, finalElementMalformed := decodeBGPPath(upd.Path)
	origin := deriveOrigin(path, finalElementMalformed)

	var out []BGPRealtimeEvent
	ordinal := 0
	for _, ann := range upd.Announcements {
		for _, prefix := range ann.Prefixes {
			if !isValidPrefix(prefix) {
				continue
			}
			out = append(out, BGPRealtimeEvent{
				ID:              sourceEventID(upd.ID, EventAnnouncement, prefix, ordinal),
				SourceMessageID: upd.ID,
				Timestamp:       ts,
				Type:            EventAnnouncement,
				Resource:        resource,
				Prefix:          prefix,
				PeerASN:         peerASN,
				Peer:            upd.Peer,
				Path:            path,
				Origin:          origin,
				Source:          "ris-live",
			})
			ordinal++
		}
	}
	for _, prefix := range upd.Withdrawals {
		if !isValidPrefix(prefix) {
			continue
		}
		out = append(out, BGPRealtimeEvent{
			ID:              sourceEventID(upd.ID, EventWithdrawal, prefix, ordinal),
			SourceMessageID: upd.ID,
			Timestamp:       ts,
			Type:            EventWithdrawal,
			Resource:        resource,
			Prefix:          prefix,
			PeerASN:         peerASN,
			Peer:            upd.Peer,
			// Path/Origin deliberadamente en su valor cero: un withdrawal
			// no trae path en el wire — nunca fabricado (roadmap §23.3).
			Source: "ris-live",
		})
		ordinal++
	}
	return out, nil
}

// isValidPrefix exige un CIDR interpretable (v1.2 P1-3 closure, caso E) —
// nunca se fabrica un announcement/withdrawal a partir de un prefix
// vacío o basura.
func isValidPrefix(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// prefixMatchesResolved reporta si wirePrefix se refiere EXACTAMENTE al
// mismo CIDR que resolvedPrefix, usando comparación canónica vía netip —
// nunca comparación de strings, que rechazaría incorrectamente formas
// IPv6 equivalentes (v1.2 Gate 3 P1-1 closure). El filtro `prefix` de
// ris_subscribe (§23.1) le pide a RIS Live que filtre por un recurso
// exacto, pero un solo mensaje UPDATE del wire puede legítimamente
// contener múltiples prefixes anunciados/retirados — TRAZIP nunca confía
// en que RIS Live haya podado el payload a exactamente lo pedido; cada
// evento decodificado se re-verifica aquí antes de poder entrar a la
// cola, disparar derivación/RPKI, o llegar al Bus.
func prefixMatchesResolved(wirePrefix, resolvedPrefix string) bool {
	if wirePrefix == "" || resolvedPrefix == "" {
		return false
	}
	wp, err := netip.ParsePrefix(wirePrefix)
	if err != nil {
		return false
	}
	rp, err := netip.ParsePrefix(resolvedPrefix)
	if err != nil {
		return false
	}
	return wp == rp
}

// sourceEventID implementa el formato congelado en el roadmap §23.3 para
// source events: "<SourceMessageID>:<Type>:<Prefix>:<Ordinal>". Múltiples
// eventos del mismo mensaje wire comparten SourceMessageID pero nunca ID.
func sourceEventID(sourceMessageID string, t BGPRealtimeEventType, prefix string, ordinal int) string {
	return fmt.Sprintf("%s:%s:%s:%d", sourceMessageID, t, prefix, ordinal)
}

// decodeBGPPath decodifica el array `path` del wire, que puede mezclar
// enteros sueltos (ASN) con arrays anidados de enteros (AS_SET). Un
// elemento que no es ni uno ni el otro se descarta — nunca fabrica un
// ASN, nunca hace panic. El orden se preserva exactamente. El segundo
// valor de retorno es true cuando el ÚLTIMO elemento crudo del wire (por
// posición original, antes de descartar nada) no fue decodificable — la
// llamadora (deriveOrigin) NUNCA debe inferir un origen a partir de lo
// que quede tras descartarlo, porque eso fabricaría que el elemento
// anterior era el verdadero final del path (v1.2 P1-3 closure, caso A).
// Un elemento malformado en cualquier OTRA posición no activa esta señal:
// el último elemento real del wire sigue siendo el que decodificó, así
// que el origen derivado de él sigue siendo honesto.
func decodeBGPPath(raw []json.RawMessage) (BGPPath, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	path := make(BGPPath, 0, len(raw))
	finalElementMalformed := false
	for i, elem := range raw {
		var asn int
		if err := json.Unmarshal(elem, &asn); err == nil {
			path = append(path, PathElement{Kind: PathElementASN, ASN: asn})
			continue
		}
		var set []int
		if err := json.Unmarshal(elem, &set); err == nil {
			path = append(path, PathElement{Kind: PathElementASSet, Set: set})
			continue
		}
		// elemento no decodificable (ni int ni []int) — descartado, nunca
		// fabricado.
		if i == len(raw)-1 {
			finalElementMalformed = true
		}
	}
	return path, finalElementMalformed
}

// deriveOrigin implementa exactamente la regla del roadmap §23.3: el
// ÚLTIMO PathElement decide. AS_SET final, path vacío, o un elemento
// final no decodificable (finalElementMalformed, v1.2 P1-3 closure) =>
// indeterminado, nunca un ASN inventado ni inferido de un path truncado.
func deriveOrigin(path BGPPath, finalElementMalformed bool) OriginResolution {
	if finalElementMalformed {
		return OriginResolution{
			Determinate: false,
			ASN:         0,
			Reason:      "elemento final del path no decodificable — origen no determinable desde un path truncado",
		}
	}
	if len(path) == 0 {
		return OriginResolution{Determinate: false, ASN: 0, Reason: "empty path"}
	}
	last := path[len(path)-1]
	switch last.Kind {
	case PathElementASN:
		return OriginResolution{Determinate: true, ASN: last.ASN}
	case PathElementASSet:
		return OriginResolution{
			Determinate: false,
			ASN:         0,
			Reason:      fmt.Sprintf("as_set final: %v, origen no determinable", last.Set),
		}
	default:
		return OriginResolution{Determinate: false, ASN: 0, Reason: "empty path"}
	}
}

// parsePeerASN parsea el peer_asn del wire, que llega como string —
// nunca asumido int (§23.1). ok=false para vacío, no numérico, o <=0
// (ASN 0 está reservado/es inválido, RFC 7607) — la llamadora nunca debe
// emitir un evento real con PeerASN=0 como si fuera evidencia válida
// (v1.2 P1-3 closure, caso B).
func parsePeerASN(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	if n <= 0 {
		return 0, false
	}
	return n, true
}

// risTimestampToRFC3339 convierte el timestamp float Unix del wire
// (con fracción de segundo) a RFC3339 con nanosegundos — nunca tratado
// como si ya fuera texto ISO (§23.1). Ausente (cero, valor por defecto de
// Go cuando el campo no viene en el JSON), no positivo, o no finito
// (NaN/Inf) devuelve "" — nunca fabricado como epoch 1970 (v1.2 P1-3
// closure, caso C).
func risTimestampToRFC3339(ts float64) string {
	if math.IsNaN(ts) || math.IsInf(ts, 0) || ts <= 0 {
		return ""
	}
	sec := int64(ts)
	nsec := int64(math.Round((ts - float64(sec)) * 1e9))
	return time.Unix(sec, nsec).UTC().Format(time.RFC3339Nano)
}

// normalizeBGPOrigin normaliza case-insensitively el atributo BGP ORIGIN
// del wire ("IGP" confirmado en mayúsculas en el probe real, manual en
// minúsculas — §23.1). No expuesto todavía en BGPRealtimeEvent (ningún
// contrato de Gate 2/3 lo consume); documentado y testeado aquí para que
// la regla de case-insensitivity no se re-derive desde cero cuando un
// gate futuro decida surfacearlo.
func normalizeBGPOrigin(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// OriginChanged implementa la regla EXACTA de origin_changed cerrada en
// v1.2 P1-1 (BGP_INTELLIGENCE_ROADMAP.md §23.3): dispara ÚNICAMENTE
// cuando ambos orígenes son determinados y el ASN difiere. Cualquier
// transición que involucre un origen indeterminado (AS_SET, path vacío)
// en cualquiera de los dos extremos queda excluida deliberadamente.
func OriginChanged(previous, current OriginResolution) bool {
	return previous.Determinate && current.Determinate && previous.ASN != current.ASN
}

// PathChanged reporta si dos BGPPath difieren estructuralmente —
// posición, Kind y contenido (ASN o Set) exactos.
func PathChanged(previous, current BGPPath) bool {
	return !pathsEqual(previous, current)
}

func pathsEqual(a, b BGPPath) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Kind != b[i].Kind {
			return false
		}
		switch a[i].Kind {
		case PathElementASN:
			if a[i].ASN != b[i].ASN {
				return false
			}
		case PathElementASSet:
			if len(a[i].Set) != len(b[i].Set) {
				return false
			}
			for j := range a[i].Set {
				if a[i].Set[j] != b[i].Set[j] {
					return false
				}
			}
		}
	}
	return true
}
