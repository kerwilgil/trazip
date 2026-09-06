package bgp

import "trazip/internal/intel/external"

// ComponentStatus is per-datasource-call state — four distinct,
// non-overlapping meanings, never collapsed into a single boolean. A
// missing component is NOT the same as one that failed, and neither is
// the same as one that never applied to begin with.
type ComponentStatus string

const (
	// ComponentOK: la consulta se hizo y devolvió un dato utilizable.
	ComponentOK ComponentStatus = "ok"

	// ComponentNotApplicable: este componente nunca se consultó — porque
	// el tipo de recurso no lo requiere, o porque el input proporcionado
	// no pasó validación local antes de intentar la consulta (ASN fuera
	// de rango, prefijo malformado, etc.). En ningún caso significa que
	// la fuente haya fallado ni que el dato falte — significa que TRAZIP
	// nunca llegó a preguntarle nada a RIPEstat.
	ComponentNotApplicable ComponentStatus = "not_applicable"

	// ComponentUnavailable: la consulta se completó correctamente
	// (RIPEstat respondió), pero la fuente no tiene el dato específico.
	ComponentUnavailable ComponentStatus = "unavailable"

	// ComponentDegraded: la consulta a la fuente se intentó y falló —
	// red, timeout, cancelación durante el request, HTTP no exitoso,
	// respuesta inválida/no interpretable. Nunca se usa para input
	// inválido rechazado antes de la consulta (eso es
	// ComponentNotApplicable) — degradado significa específicamente que
	// el datasource, no la validación local, es lo que falló.
	ComponentDegraded ComponentStatus = "degraded"
)

// ComponentEvidence is one datasource call's full provenance: which
// endpoint, what was sent, when, whether it came from cache, and its
// outcome. Every aggregate BGP Intelligence type carries these keyed by a
// stable component name instead of one ambiguous top-level Disclosure.
type ComponentEvidence struct {
	// Component is one of: "as-overview" | "announced-prefixes" |
	// "routing-status" | "rpki-validation" | "asn-neighbours" | "bgp-state"
	// — v1.2 realtime derived events (§23.3) additionally use
	// "bgp-realtime-derivation" (see SourceEventIDs below).
	Component  string              `json:"component"`
	Status     ComponentStatus     `json:"status"`
	Disclosure external.Disclosure `json:"disclosure"`
	FromCache  bool                `json:"fromCache"`
	Err        string              `json:"err,omitempty"` // solo si Status == ComponentDegraded

	// SourceEventIDs references the BGPRealtimeEvent.ID(s) (v1.2 §23.3)
	// that this evidence entry's claim is based on — populated only by
	// v1.2 realtime derived-event provenance (path_changed/origin_changed/
	// moas_appeared/moas_disappeared/rpki_transition, v1.2 Gate 3 P1-3
	// closure). omitempty and never populated by any v1.1 RIPEstat query
	// evidence (Overview/Neighbors/Topology/RPKI/etc.), which has no
	// realtime source event to reference — v1.1 JSON output is therefore
	// byte-identical to before this field existed.
	SourceEventIDs []string `json:"sourceEventIds,omitempty"`
}
