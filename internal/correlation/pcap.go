package correlation

import "trazip/internal/model"

// SourceArea names WHICH kind of underlying evidence a PcapFinding came
// from — domain-neutral, never a frontend tab/route name (Phase E.0:
// "QUITAR UI CONCERN DEL CORE"). internal/api's PCAP correlator still knows
// exactly which finding came from which engine; the frontend is the one
// that decides netdiag findings surface under a "health" tab, scan_
// detection under "detections", and so on — this package has no opinion on
// that and must never encode it.
type SourceArea string

const (
	SourceAreaNetDiag       SourceArea = "netdiag"
	SourceAreaScanDetection SourceArea = "scan_detection"
	SourceAreaFlows         SourceArea = "flows"
	SourceAreaPackets       SourceArea = "packets"
)

// PcapFinding is one evidence-backed observation about a capture — reusing
// the central model (model.Level/Confidence/Evidence) rather than a bespoke
// shape, exactly like every other TRAZIP judgement (prompt maestro §8/§10).
// Never invents a cause beyond what the underlying engine (netdiag,
// scandetect) already established — internal/api's correlator (see its own
// package placement note) correlates and prioritizes existing findings, it
// does not re-detect anything. Moved here from internal/api in Phase E.0 so
// a future Investigation package can hold one without importing
// internal/api (see this package's own doc comment).
type PcapFinding struct {
	ID          string           `json:"id"`
	Category    string           `json:"category"` // loop | broadcast_storm | duplicate_ip | rogue_dhcp | scan_vertical | scan_horizontal | top_traffic | protocol_context | tcp_resets
	Summary     string           `json:"summary"`
	Level       model.Level      `json:"level"`
	Confidence  model.Confidence `json:"confidence"`
	Evidence    []model.Evidence `json:"evidence,omitempty"`
	Limitations []string         `json:"limitations,omitempty"`
	// SourceArea is which kind of evidence backs this finding — see its own
	// doc comment. The frontend maps this to a tab; this package never
	// names one.
	SourceArea SourceArea `json:"sourceArea"`
}

// PcapSummaryStats is the plain-numbers context PcapIncidentSummary shows
// alongside its findings — counts already computed elsewhere in PcapResult,
// gathered here so the UI's "Contexto" section doesn't have to reach back
// into the full PcapResult for a handful of numbers.
type PcapSummaryStats struct {
	Packets         int `json:"packets"`
	Flows           int `json:"flows"`
	Endpoints       int `json:"endpoints"`
	PublicEndpoints int `json:"publicEndpoints"`
	// PrivateEndpoints counts only endpoints classify.Classify actually
	// labeled "private" (RFC 1918) — never a catch-all for "not public"
	// (Phase C.1 fix #2). Loopback, link-local, multicast, reserved,
	// documentation and bogon addresses are real, distinct classifications
	// classify.Classify already makes; miscounting them as "private" would
	// misrepresent what's actually in the capture (e.g. a bogon source
	// showing up as if it were an ordinary LAN host).
	PrivateEndpoints int `json:"privateEndpoints"`
	// OtherEndpoints is everything that's neither "public" nor "private" —
	// loopback/link-local/multicast/reserved/documentation/bogon/unknown.
	OtherEndpoints int    `json:"otherEndpoints"`
	GeoAvailable   bool   `json:"geoAvailable"`
	SIPDetected    bool   `json:"sipDetected"`
	TopTalker      string `json:"topTalker,omitempty"`
	TopASN         string `json:"topASN,omitempty"`
	TCPResets      int    `json:"tcpResets"`
}

// PcapIncidentSummary is "what should I look at in this capture" — built
// entirely from AnalyzePcap's own already-computed results (Phase C: "NO
// crear parser nuevo. NO volver a interpretar paquetes desde cero."). The
// correlation logic that builds one (summarizePcap) still lives in
// internal/api — see that package's own placement note — only the
// persistable result type moved here.
type PcapIncidentSummary struct {
	Summary    string           `json:"summary"`
	Level      model.Level      `json:"level"`
	Confidence model.Confidence `json:"confidence"`
	Findings   []PcapFinding    `json:"findings"`
	// Evidence/Limitations make this summary self-sufficient (Phase C.1 fix
	// #1) — a reader shouldn't have to open every finding to see what backs
	// the headline. Pooled from every finding ABOVE Info (severity-ordered,
	// deduplicated), never from Info-only context findings: those don't
	// support a negative headline, so folding their "evidence" in here
	// would fabricate the impression of a health check that never ran.
	// Empty on a clean/Info-only capture — never filled with invented
	// "everything's fine" evidence.
	Evidence    []model.Evidence `json:"evidence,omitempty"`
	Limitations []string         `json:"limitations,omitempty"`
	Stats       PcapSummaryStats `json:"stats"`
}

// ToSnapshot adapts a PcapIncidentSummary into the shared Snapshot contract
// — a pure mapping, no recomputation. subject/sourceID/occurredAt are the
// caller's to provide explicitly (e.g. a capture's display label, its
// session ID, when the analysis ran) and may all be left empty; this
// function never fabricates a local file path or any other value the
// summary itself doesn't carry (Phase E.0: "NO inventar path"). There is no
// CounterEvidence concept for a PCAP summary today, so Assessment.
// CounterEvid is always left nil.
func (s PcapIncidentSummary) ToSnapshot(subject, sourceID, occurredAt string) Snapshot {
	return Snapshot{
		SchemaVersion: SnapshotSchemaVersion,
		Kind:          SourcePCAP,
		SourceID:      sourceID,
		Subject:       subject,
		OccurredAt:    occurredAt,
		Assessment: model.Assessment{
			Conclusion:  s.Summary,
			Level:       s.Level,
			Confidence:  s.Confidence,
			Evidence:    s.Evidence,
			Limitations: s.Limitations,
		},
	}
}
