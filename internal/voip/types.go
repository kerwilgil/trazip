// Package voip correlates SIP signaling with the RTP/RTCP media it negotiates
// into Call objects (prompt maestro §9 Fase 3). It builds entirely on the
// stateless parsers in internal/protocol/{sip,sdp,rtp,rtcp}; this package owns
// all the stateful call/dialog tracking and the passive-analysis-only audio
// export gate (§16).
package voip

import (
	"time"

	"trazip/internal/model"
	"trazip/internal/protocol/rtcp"
	"trazip/internal/protocol/rtp"
	"trazip/internal/protocol/sdp"
)

// TimelineEvent is one SIP message placed on a call's timeline.
type TimelineEvent struct {
	Time           time.Time `json:"-"`
	TimeStr        string    `json:"time"`
	Src            string    `json:"src"`
	Dst            string    `json:"dst"`
	Summary        string    `json:"summary"` // "INVITE", "180 Ringing", "200 OK", ...
	Retransmission bool      `json:"retransmission,omitempty"`
}

// MOSEstimate is a coarse Mean Opinion Score with its formula and limitations
// spelled out — never presented as a precise measurement (prompt maestro §15).
type MOSEstimate struct {
	Score       float64  `json:"score"`
	Formula     string   `json:"formula"`
	Limitations []string `json:"limitations"`
}

// StreamInfo is one observed RTP media stream, optionally matched to a Call.
type StreamInfo struct {
	CallID      string `json:"callId,omitempty"`
	SSRC        uint32 `json:"ssrc"`
	Src         string `json:"src"` // ip:port
	Dst         string `json:"dst"`
	PayloadType int    `json:"payloadType"`
	CodecName   string `json:"codecName,omitempty"`
	ClockRate   int    `json:"clockRate,omitempty"`
	// MediaType is the SDP m= section's own type (audio/video/application/
	// ...) for whichever media address correlated this RTP stream — never
	// guessed from the codec name. Empty when no SDP was captured, or
	// neither end of the stream matched a negotiated media address.
	MediaType string       `json:"mediaType,omitempty"`
	Stats     rtp.Snapshot `json:"stats"`
	MOS       *MOSEstimate `json:"mos,omitempty"`
	RTCPSeen  bool         `json:"rtcpSeen"`
	// RTCPReports is every RTCP packet this capture saw that says something
	// about this stream's SSRC — filtered and, where a compound packet mixed
	// in a foreign SR or a foreign stream's report block, reconstructed to
	// strip that unrelated content out (see filterObservationsForSSRC). Not
	// the original wire bytes/packets verbatim — call it "filtered", not
	// "raw", in any comment or UI copy that references it.
	RTCPReports []rtcp.Packet `json:"rtcpReports,omitempty"`
	// RTCP is a computed, stable summary of what RTCP reported about this
	// exact stream (Src→Dst, this SSRC) — never nil unless no RTCP report
	// ever named this SSRC at all. Its two halves come from different
	// parties and must stay visibly distinct — see RTCPSummary's own
	// comment for why folding them into one flat "remote" bag was wrong.
	RTCP       *RTCPSummary `json:"rtcp,omitempty"`
	DTMFDigits string       `json:"dtmfDigits,omitempty"`
	// FirstSeen/LastSeen delimitan la identidad temporal: un SSRC puede
	// reutilizarse en otra llamada y por ello nunca es identidad suficiente.
	FirstSeen         time.Time `json:"firstSeen,omitempty"`
	LastSeen          time.Time `json:"lastSeen,omitempty"`
	PtimeMs           int       `json:"ptimeMs,omitempty"`
	AudioStatus       string    `json:"audioStatus,omitempty"`
	AudioStatusDetail string    `json:"audioStatusDetail,omitempty"`
	Direction         string    `json:"direction,omitempty"` // caller|callee|unknown_direction
}

const (
	AudioStatusReconstructable       = "reconstructable"
	AudioStatusUnsupportedCodec      = "unsupported_codec"
	AudioStatusSRTPDetected          = "srtp_detected"
	AudioStatusEncryptedUnavailable  = "encrypted_audio_unavailable"
	AudioStatusMissingSDP            = "missing_sdp"
	AudioStatusDegraded              = "degraded_reconstruction"
	AudioStatusUnsupportedG729AnnexB = "unsupported_g729_annex_b"
	AudioStatusResourceLimit         = "resource_limit_exceeded"
	AudioStatusUnknownDirection      = "unknown_direction"
)

// RTCPSummary is everything RTCP reported about one stream's SSRC, kept as
// two independently-nil halves rather than one flat struct — because they
// describe two DIFFERENT parties, not one "remote" side:
//
//   - Receiver: what the party RECEIVING this stream (Dst) reported about
//     its own reception, via RTCP Report Blocks addressed at this SSRC —
//     RFC 3550 §6.4.2. This is the only half that is actually "the other
//     side's view" of the SAME A→B traffic TRAZIP measured locally as
//     Stats. Same stream, same direction, two different vantage points —
//     never "the opposite direction" or "sentido contrario".
//   - Sender: what the party SENDING this stream (Src, this stream's own
//     origin) self-reported via its own RTCP Sender Report — RFC 3550
//     §6.4.1. This describes the SAME party TRAZIP already measures
//     locally via Stats, just self-reported instead of capture-observed —
//     never "remote", it is the local stream's own sender.
//
// A stream can have either, both, or (if it never appears in any RTCP
// report) neither. Whichever is nil MUST be treated as "no data", never
// synthesized: a Sender Report existing is not evidence of what the
// Receiver reported, and vice versa — see buildRTCPSummary's doc comment
// for the bug this specifically guards against.
type RTCPSummary struct {
	// EstimatedRTTMs is nil whenever RFC 3550's SR/RR correlation cannot be
	// established with confidence — see EstimatedRTTUnavailableReason. Never 0
	// as a stand-in for "no data": 0ms is a real (if suspicious) measurement
	// and must stay distinguishable from "could not compute".
	//
	// Named "Estimated", not "RTT", on purpose: the RFC 3550 §6.4.1 formula
	// needs A, the moment the RR arrives AT THE ORIGINAL SR's SENDER — but a
	// passive third-party capture only has ITS OWN capture-point timestamp for
	// that packet, which this code substitutes as a stand-in (see
	// estimateRTT's doc comment). The gap between the two grows with the
	// capture's network distance from the endpoint that actually receives the
	// RR, so this is never presented as an exact round-trip measurement — in
	// the UI, in Diagnose's evidence (lower confidence, ProvInferred, an
	// explicit Limitation), or in this field's own name, so a future reader
	// grepping for "RTT" without context still lands on the caveat. It
	// combines the Sender's SR with the Receiver's report block that
	// references it (matched via LSR/DLSR), so it stays populated by
	// buildRTCPSummary even in the (normal) case where Sender/Receiver below
	// each reflect only their own latest report.
	EstimatedRTTMs                *float64 `json:"estimatedRttMs,omitempty"`
	EstimatedRTTUnavailableReason string   `json:"estimatedRttUnavailableReason,omitempty"`

	// Receiver is nil unless a Report Block naming this SSRC was actually
	// observed — never synthesized from a Sender Report alone.
	Receiver *RTCPReceiverSummary `json:"receiver,omitempty"`
	// Sender is nil unless this SSRC's own Sender Report was actually
	// observed — never synthesized from a Report Block alone.
	Sender *RTCPSenderSummary `json:"sender,omitempty"`
}

// RTCPReceiverSummary is the latest RTCP Report Block naming this stream's
// SSRC (RFC 3550 §6.4.2) — the receiving party's own account of how it
// received this exact stream. All fields come from the same Report Block
// together, so unlike the old flat RTCPRemote, no field here needs its own
// pointer/omitempty to separate "really 0" from "never reported": once
// Receiver is non-nil, every field below is a real value from that report.
type RTCPReceiverSummary struct {
	// FractionLostPct is the loss percentage SINCE THE PREVIOUS REPORT ONLY
	// (RFC 3550 §6.4.2) — one interval's worth, typically a few seconds. It
	// is not comparable to StreamInfo.Stats.LossPct (TRAZIP's own
	// locally-accumulated total across the whole stream) without accounting
	// for the different window each number covers; Diagnose does not
	// attempt that comparison for exactly this reason.
	FractionLostPct float64 `json:"fractionLostPct"`
	// CumulativeLost is the one loss figure in this struct that IS a running
	// total (RFC 3550 §6.4.2: "total number of RTP data packets... that have
	// been lost since the beginning of reception") — but it's a packet
	// count, not a percentage, so still not directly comparable to LossPct.
	CumulativeLost int32  `json:"cumulativeLost"`
	HighestSeq     uint32 `json:"highestSeq"`
	// JitterTicks is the receiver's own jitter measurement, in RTP timestamp
	// units — always present once Receiver is non-nil. JitterMs is the same
	// value converted to milliseconds, but ONLY when this stream's clock rate
	// came from SDP rather than the 8kHz fallback assumption (see
	// rtp.Snapshot.ClockAssumed) — converting an assumed rate would silently
	// launder a guess into a number that looks measured.
	JitterTicks uint32   `json:"jitterTicks"`
	JitterMs    *float64 `json:"jitterMs,omitempty"`
	// LSR/DLSR are 0 whenever the receiver hadn't gotten a Sender Report yet
	// at report time — RFC 3550 §6.4.1 defines 0 as that exact meaning, so
	// unlike the fields above this needs no pointer to separate "0" from
	// "absent": both cases are the honest value to show.
	LSR  uint32 `json:"lsr,omitempty"`
	DLSR uint32 `json:"dlsr,omitempty"`
}

// RTCPSenderSummary is this stream's own latest RTCP Sender Report (RFC 3550
// §6.4.1) — self-reported packet/octet/timestamp counters from the SAME
// party TRAZIP already measures locally as StreamInfo.Stats (this stream's
// Src), not a second, remote party. All fields come from the same Sender
// Report together, so — same reasoning as RTCPReceiverSummary — no field
// needs its own pointer/omitempty: once Sender is non-nil, a real 0 in any
// of these (e.g. an SR sent before the first RTP packet went out) is exactly
// as meaningful as any other value.
type RTCPSenderSummary struct {
	PacketCount  uint32 `json:"packetCount"`
	OctetCount   uint32 `json:"octetCount"`
	NTPSeconds   uint32 `json:"ntpSeconds"`
	NTPFraction  uint32 `json:"ntpFraction"`
	RTPTimestamp uint32 `json:"rtpTimestamp"`
}

// CallParty is what TRAZIP observed about one side of a SIP dialog: the
// address it used, what it announced about itself in its own SIP messages,
// and — only for a public address with a GeoIP/ASN dataset loaded — where it
// maps to. Everything here comes from headers already in the capture or an
// offline lookup; nothing is queried over the network (prompt maestro §5.7).
type CallParty struct {
	Address      string `json:"address,omitempty"` // ip:port first observed for this side
	UserAgent    string `json:"userAgent,omitempty"`
	Server       string `json:"server,omitempty"`
	Country      string `json:"country,omitempty"`
	CountryCode  string `json:"countryCode,omitempty"`
	ASN          uint32 `json:"asn,omitempty"`
	Organization string `json:"organization,omitempty"`
}

// MediaFinding is one deterministic observation comparing what SDP negotiated
// against what the RTP traffic actually did. It never asserts a cause — NAT,
// an SBC and topology hiding can all produce the same observation legitimately
// (§9 SDP) — so Summary is phrased as an observation, not a verdict.
type MediaFinding struct {
	Level   string `json:"level"` // "info" | "warn" — how much it deviates from what was negotiated, not a security judgement
	Summary string `json:"summary"`
}

// SignalingRole is one hop's position in the SIP signaling path TRAZIP
// actually observed — distinct from Caller/Callee (who sent/received the
// dialog-initiating INVITE), since a proxy/SBC/carrier relaying between them
// changes who is on the wire without changing who dialed whom. Numbering
// multiple intermediaries ("Intermediario 1", "Intermediario 2") is a
// presentation concern the UI owns — every non-edge hop is just
// SignalingRoleIntermediary here.
type SignalingRole string

const (
	SignalingRoleOrigin       SignalingRole = "origin"
	SignalingRoleIntermediary SignalingRole = "intermediary"
	SignalingRoleDestination  SignalingRole = "destination"
)

// SignalingHop is one participant address TRAZIP actually saw carrying this
// call's SIP signaling, built exclusively from INVITE/re-INVITE evidence in
// Call.Timeline (see buildSignalingPath) — never inferred or assumed.
// UserAgent/Server are promoted only from messages this exact address sent;
// Country/CountryCode/ASN/Organization come from the same offline GeoIP/ASN
// engine every other party in TRAZIP uses, never a live query.
type SignalingHop struct {
	Address      string        `json:"address"`
	Role         SignalingRole `json:"role"`
	UserAgent    string        `json:"userAgent,omitempty"`
	Server       string        `json:"server,omitempty"`
	Country      string        `json:"country,omitempty"`
	CountryCode  string        `json:"countryCode,omitempty"`
	ASN          uint32        `json:"asn,omitempty"`
	Organization string        `json:"organization,omitempty"`
}

// Call is one correlated SIP dialog plus its matched RTP media.
type Call struct {
	CallID          string          `json:"callId"`
	From            string          `json:"from,omitempty"`
	To              string          `json:"to,omitempty"`
	Timeline        []TimelineEvent `json:"timeline"`
	Established     bool            `json:"established"`
	SetupMs         float64         `json:"setupMs,omitempty"`
	Terminated      bool            `json:"terminated"`
	DurationSec     float64         `json:"durationSec,omitempty"`
	FailureCode     int             `json:"failureCode,omitempty"`
	FailureReason   string          `json:"failureReason,omitempty"`
	ProbableCause   string          `json:"probableCause,omitempty"`
	Retransmissions int             `json:"retransmissions"`
	Authenticated   bool            `json:"authenticated"` // a challenge was seen on this dialog
	NATIssue        bool            `json:"natIssue,omitempty"`
	SDPOffer        *sdp.SDP        `json:"sdpOffer,omitempty"`
	SDPAnswer       *sdp.SDP        `json:"sdpAnswer,omitempty"`
	Streams         []StreamInfo    `json:"streams,omitempty"`
	Unidirectional  bool            `json:"unidirectional,omitempty"`

	// Caller/Callee are who sent and who received the dialog-initiating
	// INVITE — empty when the capture never showed one (mid-dialog capture).
	// UserAgent/Server are promoted from that party's own SIP headers;
	// Country/ASN/Organization come from the offline GeoIP engine when the
	// address is public and a dataset is loaded. Never populated from a live
	// query (prompt maestro §5.7).
	Caller CallParty `json:"caller,omitempty"`
	Callee CallParty `json:"callee,omitempty"`

	// SignalingPath is the full chain of SIP participants TRAZIP actually
	// observed carrying this call's signaling — origin, zero or more
	// intermediaries (proxy/SBC/carrier), and destination — built from
	// INVITE/re-INVITE evidence in Timeline only (see buildSignalingPath).
	// Nil when the capture started mid-dialog (no INVITE observed) or the
	// evidence doesn't establish even a two-party path. Caller/Callee above
	// keep their existing meaning unchanged; this is an explicit, additional
	// representation for topologies with proxies/SBCs in between.
	SignalingPath []SignalingHop `json:"signalingPath,omitempty"`
	// SignalingPathComplete is false when SignalingPath's last hop is only
	// the last confidently-known participant before a SIP fork TRAZIP could
	// not resolve — never promoted to Role=destination without evidence
	// (the call's own outcome — see failureOriginAddr/establishedByAddr)
	// that it actually is the call's final endpoint.
	SignalingPathComplete bool `json:"signalingPathComplete,omitempty"`
	// FailureOrigin is the ip:port that actually sent the SIP response
	// recorded in FailureCode/FailureReason — the true responder, which can
	// differ from Callee when a proxy/SBC/carrier relays that response
	// onward. Empty when FailureCode is 0 or the responder's address could
	// not be established.
	FailureOrigin string `json:"failureOrigin,omitempty"`

	// MediaFindings compares what SDP negotiated against what the RTP traffic
	// actually did (§9 SDP "detección de discrepancias").
	MediaFindings []MediaFinding `json:"mediaFindings,omitempty"`

	// Diagnosis is the single evidence-based conclusion for this call, built
	// from every signal above. Reuses the central Assessment shape (prompt
	// maestro §8/§10) rather than a bespoke one, so it renders with the same
	// conventions as every other TRAZIP judgement.
	Diagnosis *model.Assessment `json:"diagnosis,omitempty"`

	inviteAt  time.Time
	startedAt time.Time
	endedAt   time.Time
	seenTx    map[string]bool

	// hopHeaders/failureOriginAddr/establishedByAddr are raw evidence
	// gathered during correlation (handleSIP) purely to build SignalingPath
	// and FailureOrigin in finalize — never exported directly, and never
	// used to alter Caller/Callee's own, separate meaning.
	hopHeaders        map[string]hopHeaderInfo
	failureOriginAddr string
	establishedByAddr string

	// headerProvenance is who FIRST emitted a given User-Agent/Server
	// value for a given logical SIP message instance — the dedup state
	// applyPartyHeaders and recordHopHeaders both consult before
	// attributing a header to whichever address happened to send it, so a
	// proxy that relays an unchanged header never gains a false identity
	// of its own (V1 hardening finding #2). See claimHeaderProvenance.
	headerProvenance map[headerProvenanceKey]string
}

// hopHeaderInfo is the User-Agent/Server TRAZIP saw a given address itself
// send, keyed by that address in Call.hopHeaders — unlike applyPartyHeaders
// (which only tracks Caller/Callee), this covers any address that sent a
// message on this call, so an intermediary proxy/SBC gets its own identity
// in SignalingHop too.
type hopHeaderInfo struct {
	UserAgent string
	Server    string
}

// headerProvenanceKey identifies one logical SIP message instance as it
// propagates hop by hop — deliberately NOT ViaBranch (a proxy adds/changes
// the top Via on every hop by design, so using it as identity would make
// every hop look like a "different" message and defeat the whole point of
// this dedup) and deliberately NOT the sending address (that's exactly
// what provenance is trying to determine). CSeqNum/CSeqMethod/IsRequest/
// StatusCode/FromTag/ToTag together identify the same request or the same
// response as it's relayed onward — a forwarded message keeps every one of
// these unchanged, while a genuinely different transaction (a BYE vs. the
// INVITE, a different fork's ToTag, a later re-INVITE) differs in at least
// one of them.
type headerProvenanceKey struct {
	cseqNum    int
	cseqMethod string
	isRequest  bool
	statusCode int
	fromTag    string
	toTag      string
	header     string
	value      string
}

// Result is the full analysis of a capture.
type Result struct {
	Calls       []Call      `json:"calls"`
	TotalCalls  int         `json:"totalCalls"`
	Established int         `json:"established"`
	Failed      int         `json:"failed"`
	Audit       AuditResult `json:"audit"`
}

type AuditFinding struct {
	Level      string `json:"level"`
	Category   string `json:"category"`
	CallID     string `json:"callId,omitempty"`
	Summary    string `json:"summary"`
	Evidence   string `json:"evidence,omitempty"`
	Confidence uint8  `json:"confidence"`
}

type AuditResult struct {
	Findings []AuditFinding `json:"findings"`
	High     int            `json:"high"`
	Medium   int            `json:"medium"`
	Low      int            `json:"low"`
}
