package voip

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"trazip/internal/intel/classify"
	"trazip/internal/intel/geoip"
	"trazip/internal/pcap"
	"trazip/internal/protocol/rtcp"
	"trazip/internal/protocol/rtp"
	"trazip/internal/protocol/sdp"
	"trazip/internal/protocol/sip"
)

// Analyze reads a capture file and correlates SIP+SDP+RTP+RTCP into calls. It
// walks the file twice: pass 1 builds calls and their negotiated SDP (so media
// addresses and codec clock rates are known); pass 2 reads RTP/RTCP, using
// those clock rates from the start — jitter (RFC 3550 §A.8) mixes wall-clock
// deltas scaled by clock rate with raw RTP timestamp deltas, so the rate must
// be right from the first sample, not corrected afterwards.
//
// geo is the shared offline GeoIP/ASN engine (nil is fine — every enrichment
// degrades cleanly). Both TRAZIP's GUI and any future CLI call this exact
// function with the exact same engine instance, so the two never disagree
// about what a capture means (prompt maestro §6, §15 "consistencia GUI/CLI").
func Analyze(ctx context.Context, path string, geo *geoip.Engine) (Result, error) {
	calls := make(map[string]*Call)

	if _, err := pcap.ReadPackets(ctx, path, func(_ int, p gopacket.Packet) {
		srcIP, dstIP, srcPort, dstPort, payload, ok := udpTuple(p)
		if !ok || !sip.LooksLikeSIP(payload) {
			return
		}
		if msg, err := sip.Parse(payload); err == nil {
			handleSIP(calls, msg, p.Metadata().Timestamp, srcIP, srcPort, dstIP, dstPort)
		}
	}); err != nil {
		return Result{}, err
	}
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}

	// addrToCalls answers "which call(s) negotiated this ip:port" for
	// callForMedia. Codec/media-type metadata is NOT taken from a global
	// address index any more — it is resolved per stream from that stream's
	// own call + m= section (resolveMediaForStream), so two calls reusing an
	// endpoint with the same dynamic PT never inherit each other's codec.
	addrToCalls, _, _ := buildAddressIndex(calls)

	streams := make(map[string]*rtp.Stream)
	streamMeta := make(map[string]*streamCtx)
	rtcpReports := make(map[string][]rtcpObservation)
	dtmfDigits := make(map[string]string)

	if _, err := pcap.ReadPackets(ctx, path, func(_ int, p gopacket.Packet) {
		srcIP, dstIP, srcPort, dstPort, payload, ok := udpTuple(p)
		if !ok || len(payload) == 0 || sip.LooksLikeSIP(payload) {
			return
		}
		ts := p.Metadata().Timestamp
		src := fmt.Sprintf("%s:%d", srcIP, srcPort)
		dst := fmt.Sprintf("%s:%d", dstIP, dstPort)

		// RTCP must be classified before RTP: both use version 2 and a generic
		// RTP header parser can otherwise accept SR/RR packets as media.
		if len(payload) >= 2 && payload[1] >= rtcp.TypeSR && payload[1] <= rtcp.TypeAPP {
			if reports, err := rtcp.ParseCompound(payload); err == nil {
				key := srcIP + "-" + dstIP
				for _, r := range reports {
					rtcpReports[key] = append(rtcpReports[key], rtcpObservation{Packet: r, Arrival: ts})
				}
				return
			}
		}
		if h, err := rtp.ParseHeader(payload); err == nil {
			callID := callForMedia(addrToCalls, calls, src, dst, ts)
			if callID == "" {
				return
			} // nunca mezclar media ambigua entre llamadas.
			key := fmt.Sprintf("%s|%s>%s|%08x", callID, src, dst, h.SSRC)
			st := streams[key]
			if st == nil {
				rm := resolveMediaForStream(calls[callID], src, dst, h.PayloadType)
				st = rtp.NewStream(h.SSRC, rm.clockRate)
				streams[key] = st
				streamMeta[key] = &streamCtx{callID: callID, src: src, dst: dst, payloadType: h.PayloadType, media: &rm}
			}
			st.Add(rtp.Sample{Header: *h, Arrival: ts})

			if streamMeta[key].media.codecName == "telephone-event" {
				if body := rtp.Payload(payload, h); len(body) >= 4 {
					if ev, ok := rtp.DecodeDTMFEvent(body); ok && ev.EndOfEvent {
						dtmfDigits[key] += ev.Digit
					}
				}
			}
			return
		}
	}); err != nil {
		return Result{}, err
	}

	attachStreams(calls, nil, nil, nil, streams, streamMeta, rtcpReports, dtmfDigits)
	return finalize(calls, geo), nil
}

type streamCtx struct {
	callID      string
	src, dst    string
	payloadType int
	// media is this stream's metadata resolved from ITS OWN m= section of
	// ITS OWN call (Call-ID + connAddr:port + PT). Populated by Analyze's
	// RTP pass; nil only on the legacy direct-attachStreams test path, which
	// still falls back to the address-indexed helpers.
	media *resolvedMedia
}

// resolvedMedia is the media metadata for one RTP stream, taken exclusively
// from the single SDP m= section that stream's own address negotiated inside
// its own dialog — never from any other audio section of the same Call-ID,
// and never from another call that happens to reuse the same ip:port:PT.
type resolvedMedia struct {
	codecName string
	clockRate int
	mediaType string // lower-case SDP m= type; "" when no m-line owned the address
	proto     string // "RTP/AVP", "RTP/SAVPF", …; "" when no m-line owned the address
	fmtp      string
	ptimeMs   int
	matched   bool
}

// resolveMediaForStream picks the m= section this RTP stream belongs to by
// matching the flow's own endpoints (dst first, then src — the media targets
// the receiver's negotiated connection address) against each negotiated
// "connAddr:port" of THIS call, then reads codec/proto/ptime/fmtp from that
// section only. Iteration is order-deterministic (dst before src, offer
// before answer, SDP media order) so two calls reusing an endpoint can never
// resolve to each other's codec via Go's randomized map order. Falls back to
// the RFC 3551 static table for a payload type no matched section listed.
func resolveMediaForStream(call *Call, src, dst string, pt int) resolvedMedia {
	var rm resolvedMedia
	if call != nil {
		for _, want := range []string{dst, src} {
			for _, desc := range []*sdp.SDP{call.SDPOffer, call.SDPAnswer} {
				if desc == nil {
					continue
				}
				for i := range desc.Media {
					m := &desc.Media[i]
					if m.ConnAddr == "" || fmt.Sprintf("%s:%d", m.ConnAddr, m.Port) != want {
						continue
					}
					if rm.matched {
						continue
					}
					rm.matched = true
					rm.mediaType = strings.ToLower(m.Type)
					rm.proto = m.Proto
					rm.ptimeMs = m.PtimeMs
					if c, ok := m.Codecs[pt]; ok {
						rm.codecName, rm.clockRate, rm.fmtp = c.Name, c.ClockRate, c.FMTP
					}
				}
			}
			if rm.matched {
				break
			}
		}
	}
	if rm.codecName == "" {
		if c, ok := sdp.StaticCodec(pt); ok {
			rm.codecName = c.Name
			if rm.clockRate == 0 {
				rm.clockRate = c.ClockRate
			}
		}
	}
	return rm
}

// udpTuple extracts the addressing + payload TRAZIP needs from a decoded
// packet. Only UDP is handled: RTP/RTCP are always UDP, and while SIP can run
// over TCP, VoIP troubleshooting captures are overwhelmingly UDP SIP — TCP/TLS
// SIP is a documented limitation, not a silent gap.
func udpTuple(p gopacket.Packet) (srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, ok bool) {
	udp, isUDP := p.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !isUDP {
		return "", "", 0, 0, nil, false
	}
	nl := p.NetworkLayer()
	if nl == nil {
		return "", "", 0, 0, nil, false
	}
	f := nl.NetworkFlow()
	return f.Src().String(), f.Dst().String(), uint16(udp.SrcPort), uint16(udp.DstPort), udp.Payload, true
}

func handleSIP(calls map[string]*Call, msg *sip.Message, ts time.Time, srcIP string, srcPort uint16, dstIP string, dstPort uint16) {
	if msg.CallID == "" {
		return
	}
	c := calls[msg.CallID]
	if c == nil {
		c = &Call{CallID: msg.CallID, seenTx: make(map[string]bool), hopHeaders: make(map[string]hopHeaderInfo), headerProvenance: make(map[headerProvenanceKey]string)}
		calls[msg.CallID] = c
	}

	txKey := fmt.Sprintf("%d|%s|%s|%v|%d", msg.CSeqNum, msg.CSeqMethod, msg.ViaBranch, msg.IsRequest, msg.StatusCode)
	retransmission := c.seenTx[txKey]
	c.seenTx[txKey] = true
	if retransmission {
		c.Retransmissions++
	}

	src := fmt.Sprintf("%s:%d", srcIP, srcPort)
	dst := fmt.Sprintf("%s:%d", dstIP, dstPort)
	c.Timeline = append(c.Timeline, TimelineEvent{
		Time: ts, TimeStr: ts.Format(time.RFC3339Nano), Src: src, Dst: dst,
		Summary: sipSummary(msg), Retransmission: retransmission,
	})

	if msg.Challenged {
		c.Authenticated = true
	}
	if msg.From != "" && c.From == "" {
		c.From = msg.From
	}
	if msg.To != "" {
		c.To = msg.To
	}
	applyPartyHeaders(c, msg, src)
	recordHopHeaders(c, msg, src)

	switch {
	case msg.IsRequest && msg.Method == "INVITE":
		if c.inviteAt.IsZero() {
			c.inviteAt = ts
		}
		// The dialog-initiating INVITE fixes who is Caller and who is Callee —
		// set once, from the first INVITE seen for this Call-ID. A capture that
		// starts mid-dialog never sees one, and Caller/Callee stay empty; the
		// rest of the call is still analyzed normally.
		if c.Caller.Address == "" {
			c.Caller.Address = src
			c.Callee.Address = dst
			// The INVITE itself may carry User-Agent, and applyPartyHeaders ran
			// above before Caller.Address existed to match against — apply it
			// again now that the address is known.
			applyPartyHeaders(c, msg, src)
		}
		if msg.ContentType == "application/sdp" && len(msg.Body) > 0 && c.SDPOffer == nil {
			c.SDPOffer = sdp.Parse(msg.Body)
		}
		if host := contactHost(msg.Contact); host != "" {
			if a, err := netip.ParseAddr(srcIP); err == nil && host != srcIP {
				if h, err2 := netip.ParseAddr(host); err2 == nil && classify.IsPublic(a) != classify.IsPublic(h) {
					c.NATIssue = true
				}
			}
		}

	case !msg.IsRequest && msg.CSeqMethod == "INVITE":
		if msg.StatusCode == 200 {
			if !c.Established {
				c.Established = true
				c.startedAt = ts
				c.establishedByAddr = src
				if !c.inviteAt.IsZero() {
					c.SetupMs = round2(ts.Sub(c.inviteAt).Seconds() * 1000)
				}
			}
			if msg.ContentType == "application/sdp" && len(msg.Body) > 0 && c.SDPAnswer == nil {
				c.SDPAnswer = sdp.Parse(msg.Body)
			}
		} else if msg.StatusCode >= 300 && !c.Established && c.FailureCode == 0 {
			c.FailureCode = msg.StatusCode
			c.FailureReason = msg.Reason
			c.ProbableCause = failureCause(msg.StatusCode, msg.Reason)
			c.failureOriginAddr = src
		}

	case msg.IsRequest && msg.Method == "BYE":
		c.Terminated = true
		c.endedAt = ts

	case msg.IsRequest && msg.Method == "CANCEL" && !c.Established:
		c.ProbableCause = "Llamada cancelada por el emisor antes de establecerse"
	}
}

// claimHeaderProvenance reports whether src is (or already was) the FIRST
// address observed to emit header=value for this logical SIP message
// instance — the shared decision applyPartyHeaders and recordHopHeaders
// both consult, so fixing one without the other could never leave the
// other silently contaminated (V1 hardening finding #2). A proxy that
// relays the exact same header value onward never gets an attribution of
// its own — the same request/response, one hop later, is still the SAME
// logical message under headerProvenanceKey. An intermediary that
// introduces or rewrites the value to something different gets its own key
// (the value differs) and is free to claim it as genuinely its own
// evidence. Retransmissions of the same message from the same address
// simply re-confirm that address's own, already-held claim.
func (c *Call) claimHeaderProvenance(msg *sip.Message, header, value, src string) bool {
	if c.headerProvenance == nil {
		c.headerProvenance = make(map[headerProvenanceKey]string)
	}
	key := headerProvenanceKey{
		cseqNum: msg.CSeqNum, cseqMethod: msg.CSeqMethod, isRequest: msg.IsRequest,
		statusCode: msg.StatusCode, fromTag: msg.FromTag, toTag: msg.ToTag,
		header: header, value: value,
	}
	if existing, ok := c.headerProvenance[key]; ok {
		return existing == src
	}
	c.headerProvenance[key] = src
	return true
}

// applyPartyHeaders promotes User-Agent/Server from msg into whichever party
// (Caller or Callee) sent it, matched by the packet's own source address —
// the same Headers map the SIP parser already builds, just read here instead
// of discarded. It keeps the FIRST non-empty value seen per field: a later,
// different value from the same address is never applied over an existing
// one, so this can never silently present one value while a contradictory one
// was also seen (a known simplification — see CONTEXT-trazip.md). Also
// consults claimHeaderProvenance so a party address that merely forwarded a
// header it received from elsewhere (e.g. Caller == Callee across a
// loopback capture, or a re-INVITE relayed by something upstream) is never
// credited with a header it didn't itself originate.
func applyPartyHeaders(c *Call, msg *sip.Message, src string) {
	var party *CallParty
	switch src {
	case c.Caller.Address:
		party = &c.Caller
	case c.Callee.Address:
		party = &c.Callee
	default:
		return
	}
	if ua := strings.TrimSpace(msg.Headers["user-agent"]); ua != "" && party.UserAgent == "" {
		if c.claimHeaderProvenance(msg, "user-agent", ua, src) {
			party.UserAgent = ua
		}
	}
	if srv := strings.TrimSpace(msg.Headers["server"]); srv != "" && party.Server == "" {
		if c.claimHeaderProvenance(msg, "server", srv, src) {
			party.Server = srv
		}
	}
}

// recordHopHeaders promotes User-Agent/Server for buildSignalingPath's hop
// enrichment — unlike applyPartyHeaders (Caller/Callee only), this keys by
// whichever address actually sent the message, so an intermediary
// proxy/SBC between Caller and Callee gets its own identity too. First
// non-empty value per address/field wins, same policy as applyPartyHeaders
// — and the same claimHeaderProvenance gate: a proxy relaying an unchanged
// header from an earlier hop never gains that header as its own identity
// (V1 hardening finding #2).
func recordHopHeaders(c *Call, msg *sip.Message, src string) {
	info := c.hopHeaders[src]
	changed := false
	if ua := strings.TrimSpace(msg.Headers["user-agent"]); ua != "" && info.UserAgent == "" {
		if c.claimHeaderProvenance(msg, "user-agent", ua, src) {
			info.UserAgent = ua
			changed = true
		}
	}
	if srv := strings.TrimSpace(msg.Headers["server"]); srv != "" && info.Server == "" {
		if c.claimHeaderProvenance(msg, "server", srv, src) {
			info.Server = srv
			changed = true
		}
	}
	if changed {
		c.hopHeaders[src] = info
	}
}

func sipSummary(m *sip.Message) string {
	if m.IsRequest {
		return m.Method
	}
	return fmt.Sprintf("%d %s", m.StatusCode, m.Reason)
}

// contactHost extracts the host part of a SIP Contact header, e.g.
// `<sip:alice@203.0.113.5:5060>` -> "203.0.113.5".
func contactHost(contact string) string {
	idx := strings.Index(contact, "sip:")
	if idx < 0 {
		idx = strings.Index(contact, "sips:")
		if idx < 0 {
			return ""
		}
		idx += 5
	} else {
		idx += 4
	}
	rest := contact[idx:]
	if at := strings.IndexByte(rest, '@'); at >= 0 {
		rest = rest[at+1:]
	}
	if strings.HasPrefix(rest, "[") {
		if end := strings.IndexByte(rest, ']'); end > 1 {
			return rest[1:end]
		}
		return ""
	}
	end := len(rest)
	for i, ch := range rest {
		if ch == '>' || ch == ';' || ch == ':' {
			end = i
			break
		}
	}
	if end > len(rest) {
		end = len(rest)
	}
	return rest[:end]
}

func failureCause(code int, reason string) string {
	switch code {
	case 403:
		return "Prohibido"
	case 404:
		return "Usuario no encontrado"
	case 408:
		return "Timeout de la petición"
	case 480:
		return "Temporalmente no disponible"
	case 486:
		return "Ocupado (Busy Here)"
	case 487:
		return "Petición cancelada"
	case 503:
		return "Servicio no disponible"
	case 603:
		return "Rechazada globalmente"
	default:
		switch {
		case code >= 600:
			return "Fallo global: " + reason
		case code >= 500:
			return "Fallo del servidor: " + reason
		case code >= 400:
			return "Fallo del cliente: " + reason
		default:
			return reason
		}
	}
}

// codecInfo pairs a codec with its clock rate for the address index below.
type codecInfo struct {
	name      string
	clockRate int
}

// buildAddressIndex maps every negotiated "ip:port" from every call's SDP
// offer/answer to that call's ID, plus a payload-type -> codec table per
// address (so pass 2 can look up the right clock rate before creating a
// Stream) and the m= section's own media type (audio/video/application/...)
// per address, so an RTP stream correlated to that address inherits the
// SAME classification the SDP itself already made — never re-derived by
// guessing from the codec name.
func buildAddressIndex(calls map[string]*Call) (addrToCall map[string][]string, addrCodec map[string]map[int]codecInfo, addrMediaType map[string]string) {
	addrToCall = make(map[string][]string)
	addrCodec = make(map[string]map[int]codecInfo)
	addrMediaType = make(map[string]string)

	collect := func(id string, s *sdp.SDP) {
		if s == nil {
			return
		}
		for _, m := range s.Media {
			if m.ConnAddr == "" {
				continue
			}
			key := fmt.Sprintf("%s:%d", m.ConnAddr, m.Port)
			addrToCall[key] = append(addrToCall[key], id)
			if addrMediaType[key] == "" {
				addrMediaType[key] = strings.ToLower(m.Type)
			}
			if addrCodec[key] == nil {
				addrCodec[key] = make(map[int]codecInfo)
			}
			for pt, c := range m.Codecs {
				addrCodec[key][pt] = codecInfo{name: c.Name, clockRate: c.ClockRate}
			}
		}
	}
	for id, c := range calls {
		collect(id, c.SDPOffer)
		collect(id, c.SDPAnswer)
	}
	return addrToCall, addrCodec, addrMediaType
}

// callForMedia selecciona una llamada por SDP y su ventana SIP ANTES de
// agrupar RTP. Si dos diálogos son plausibles, falla cerrado para no mezclar.
func callForMedia(index map[string][]string, calls map[string]*Call, src, dst string, at time.Time) string {
	ids := append(append([]string(nil), index[dst]...), index[src]...)
	seen := make(map[string]bool)
	var matches []string
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		c := calls[id]
		if c == nil {
			continue
		}
		start, end := c.startedAt, c.endedAt
		if start.IsZero() && len(c.Timeline) > 0 {
			start = c.Timeline[0].Time
		}
		if end.IsZero() && len(c.Timeline) > 0 {
			end = c.Timeline[len(c.Timeline)-1].Time
		}
		if start.IsZero() || end.IsZero() || (!at.Before(start.Add(-2*time.Second)) && !at.After(end.Add(2*time.Second))) {
			matches = append(matches, id)
		}
	}
	if len(matches) == 1 {
		return matches[0]
	}
	return ""
}

// mediaTypeFor looks up the SDP-declared media type for a stream by
// checking both ends of the flow against the address index — the same
// dst-then-src fallback pattern codecName/codecClockRate already use, so a
// stream inherits its classification consistently regardless of which end
// happened to be the one SDP's connection address matched.
func mediaTypeFor(addrMediaType map[string]string, src, dst string) string {
	if t, ok := addrMediaType[dst]; ok && t != "" {
		return t
	}
	if t, ok := addrMediaType[src]; ok && t != "" {
		return t
	}
	return ""
}

// codecClockRate looks up the clock rate for a payload type by checking both
// ends of a flow against the address index, falling back to the RFC 3551
// static table. Zero tells rtp.NewStream to use and flag its documented
// 8000 Hz assumption.
func codecClockRate(addrCodec map[string]map[int]codecInfo, src, dst string, pt int) int {
	if m, ok := addrCodec[dst]; ok {
		if c, ok := m[pt]; ok && c.clockRate > 0 {
			return c.clockRate
		}
	}
	if m, ok := addrCodec[src]; ok {
		if c, ok := m[pt]; ok && c.clockRate > 0 {
			return c.clockRate
		}
	}
	if c, ok := sdp.StaticCodec(pt); ok && c.ClockRate > 0 {
		return c.ClockRate
	}
	return 0
}

func codecName(addrCodec map[string]map[int]codecInfo, src, dst string, pt int) string {
	if m, ok := addrCodec[dst]; ok {
		if c, ok := m[pt]; ok && c.name != "" {
			return c.name
		}
	}
	if m, ok := addrCodec[src]; ok {
		if c, ok := m[pt]; ok && c.name != "" {
			return c.name
		}
	}
	if c, ok := sdp.StaticCodec(pt); ok {
		return c.Name
	}
	return ""
}

func attachStreams(
	calls map[string]*Call,
	legacyAddrToCall map[string]string, // solo compatibilidad de pruebas históricas.
	addrCodec map[string]map[int]codecInfo,
	addrMediaType map[string]string,
	streams map[string]*rtp.Stream,
	meta map[string]*streamCtx,
	rtcpReports map[string][]rtcpObservation,
	dtmf map[string]string,
) {
	for key, st := range streams {
		mt := meta[key]
		if mt == nil {
			continue
		}
		snap := st.Snapshot()

		callID, matched := mt.callID, mt.callID != ""
		if !matched && legacyAddrToCall != nil {
			callID, matched = legacyAddrToCall[mt.dst]
			if !matched {
				callID, matched = legacyAddrToCall[mt.src]
			}
		}
		rm := resolvedMedia{}
		if mt.media != nil {
			rm = *mt.media
		} else {
			// Legacy direct-attachStreams test path: the address-indexed
			// helpers still answer codec/clock/media-type (no per-m-line
			// proto or fmtp, exactly as before this change).
			rm = resolvedMedia{
				codecName: codecName(addrCodec, mt.src, mt.dst, mt.payloadType),
				clockRate: codecClockRate(addrCodec, mt.src, mt.dst, mt.payloadType),
				mediaType: mediaTypeFor(addrMediaType, mt.src, mt.dst),
			}
		}
		name := rm.codecName
		mediaType := rm.mediaType
		clockRate := snap.ClockRate

		// rtcpReports is gathered per IP pair (see the comment on
		// filterObservationsForSSRC) — several RTP streams, each with its own
		// SSRC, can share the same two addresses on different ports, so this
		// slice may still describe more than just st.SSRC before filtering.
		// Narrowing it here, once, means every consumer below — the filtered
		// RTCPReports this stream exposes, and buildRTCPSummary/estimateRTT —
		// sees only this stream's own RTCP, never a sibling stream's on the
		// same IP pair.
		fwdKey, revKey := ipOf(mt.src)+"-"+ipOf(mt.dst), ipOf(mt.dst)+"-"+ipOf(mt.src)
		obs := append([]rtcpObservation(nil), rtcpReports[fwdKey]...)
		// When src and dst share the same IP (different ports), fwdKey and
		// revKey are identical — appending rtcpReports[revKey] again would
		// duplicate every observation in that bucket, inflating RTCPReports,
		// SR/RR counts, and everything filterObservationsForSSRC/
		// buildRTCPSummary derive from them.
		if revKey != fwdKey {
			obs = append(obs, rtcpReports[revKey]...)
		}
		obs = filterObservationsForSSRC(obs, st.SSRC)
		reports := make([]rtcp.Packet, len(obs))
		for i, o := range obs {
			reports[i] = o.Packet
		}
		info := StreamInfo{
			CallID: callID, SSRC: st.SSRC, Src: mt.src, Dst: mt.dst, PayloadType: mt.payloadType,
			CodecName: name, ClockRate: clockRate, MediaType: mediaType, Stats: snap,
			FirstSeen: snap.FirstSeen, LastSeen: snap.LastSeen,
			RTCPSeen:    len(reports) > 0,
			RTCPReports: reports,
			RTCP:        buildRTCPSummary(obs, st.SSRC, clockRate, snap.ClockAssumed),
			DTMFDigits:  dtmf[key],
		}
		info.AudioStatus, info.AudioStatusDetail = streamAudioStatus(rm, calls[callID])
		info.PtimeMs = rm.ptimeMs
		if info.PtimeMs == 0 {
			info.PtimeMs = callPtime(calls[callID])
		}
		info.Direction = mediaDirection(calls[callID], mt.src)
		if info.Direction == "unknown_direction" && info.AudioStatus == AudioStatusReconstructable {
			info.AudioStatus = AudioStatusUnknownDirection
		}
		// EstimateMOS is a voice-quality model (E-model/G.107/G.113 baseline
		// for G.711) — meaningless for video or any other non-audio media,
		// so it's never computed at all outside audio, not just hidden in
		// the UI. mediaType == "" (SDP never captured, or the address never
		// matched a media section) is treated as audio for backward
		// compatibility with captures/tests that predate this field —
		// exactly the same signals (Received>=20) already gated it before.
		if snap.Received >= 20 && (mediaType == "" || mediaType == "audio") {
			m := EstimateMOS(snap.LossPct, snap.JitterMs)
			info.MOS = &m
		}

		if matched {
			calls[callID].Streams = append(calls[callID].Streams, info)
		}
	}
}

func ipOf(hostport string) string {
	if i := strings.LastIndexByte(hostport, ':'); i > 0 {
		return hostport[:i]
	}
	return hostport
}

// directionKey is a canonical representation of one stream's flow direction,
// used to detect whether some other stream is its exact reverse. Ordinarily
// just the two IPs — a stream's port varies per call/SSRC and isn't part of
// "which direction" — but when Src and Dst share the same IP (a loopback
// test capture, or genuinely the same host on both legs), IP alone can't
// distinguish forward from reverse at all: every such stream reduces to the
// SAME [ip,ip] pair regardless of its real direction, which would make a
// single one-way loopback stream look bidirectional against itself. The
// full endpoint (ip:port) is used instead in that case, which DOES differ
// between an outbound leg and its genuine return leg even on localhost.
func directionKey(s StreamInfo) [2]string {
	srcIP, dstIP := ipOf(s.Src), ipOf(s.Dst)
	if srcIP == dstIP {
		return [2]string{s.Src, s.Dst}
	}
	return [2]string{srcIP, dstIP}
}

// hasBothDirections reports whether streams cover both directions of a
// conversation (some A->B and some B->A), not just how many streams exist.
// Two streams don't prove two directions: two SSRCs, or audio+video, or a
// mid-call SSRC change can all produce several streams in the SAME
// direction. Uses only the streams' own observed Src/Dst — no SIP-role
// guessing — so a call this can't determine anything stronger about simply
// isn't called unidirectional based on a wrong signal.
func hasBothDirections(streams []StreamInfo) bool {
	seen := make(map[[2]string]bool, len(streams))
	for _, s := range streams {
		seen[directionKey(s)] = true
	}
	for k := range seen {
		if seen[[2]string{k[1], k[0]}] {
			return true
		}
	}
	return false
}

func finalize(calls map[string]*Call, geo *geoip.Engine) Result {
	var out []Call
	established, failed := 0, 0
	for _, c := range calls {
		sort.Slice(c.Timeline, func(i, j int) bool { return c.Timeline[i].Time.Before(c.Timeline[j].Time) })
		if !c.startedAt.IsZero() && !c.endedAt.IsZero() {
			c.DurationSec = round2(c.endedAt.Sub(c.startedAt).Seconds())
		}
		if c.Established {
			established++
			// Unidirectional is documented and surfaced everywhere (audit.go's
			// "Audio RTP unidireccional" finding, the UI's "audio
			// unidireccional" label) as being SPECIFICALLY about audio — so
			// it's computed from audio streams only, and left false entirely
			// for a call with no audio at all, rather than computed from
			// whatever media happens to exist and mislabeled. A call with
			// audio A->B and video B->A must still read as one-way audio:
			// video covering the missing direction doesn't mean the audio did.
			audioStreams := audioOnlyStreams(c.Streams)
			if len(audioStreams) > 0 && !hasBothDirections(audioStreams) {
				c.Unidirectional = true
			}
		}
		if c.FailureCode > 0 {
			failed++
		}
		sort.Slice(c.Streams, func(i, j int) bool { return c.Streams[i].Src < c.Streams[j].Src })

		enrichParty(&c.Caller, geo)
		enrichParty(&c.Callee, geo)

		if c.FailureCode > 0 {
			c.FailureOrigin = c.failureOriginAddr
		}
		c.SignalingPath, c.SignalingPathComplete = buildSignalingPath(c)
		for i := range c.SignalingPath {
			enrichHop(&c.SignalingPath[i], geo)
		}

		c.MediaFindings = compareMediaToRTP(c)
		diag := Diagnose(*c)
		c.Diagnosis = &diag

		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Timeline) == 0 || len(out[j].Timeline) == 0 {
			return out[i].CallID < out[j].CallID
		}
		return out[i].Timeline[0].Time.Before(out[j].Timeline[0].Time)
	})
	res := Result{Calls: out, TotalCalls: len(out), Established: established, Failed: failed}
	res.Audit = AuditCalls(out)
	return res
}

func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100
}
