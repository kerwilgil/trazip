package voip

import (
	"fmt"
	"strings"

	"trazip/internal/protocol/sdp"
)

// compareMediaToRTP checks what SDP negotiated against what the RTP traffic
// actually did (prompt maestro §9 SDP "detección de discrepancias entre
// señalización y tráfico RTP observado"). Every finding is phrased as an
// observation, never a verdict: NAT, an SBC and topology hiding can all
// produce the exact same difference legitimately, so the wording says
// "diferencia observada" / "posible" / "requiere interpretación", not "error".
func compareMediaToRTP(c *Call) []MediaFinding {
	pairs := buildMediaPairs(c.SDPOffer, c.SDPAnswer)
	if len(pairs) == 0 || len(c.Streams) == 0 {
		return nil
	}

	var findings []MediaFinding
	for _, s := range c.Streams {
		findings = append(findings, compareStreamToSDP(s, pairs)...)
	}
	return findings
}

// mediaPair is one m= section by POSITION — RFC 3264 requires the answer to
// carry the same number of m-lines as the offer, in the same order, each
// answer line corresponding to the offer line at the same index (even a
// rejected section keeps its position, marked with port 0). Position, not
// "first audio", is therefore the only correct way to associate an offer
// section with its answer: a session with m=audio then m=video would
// otherwise compare a video stream against the offer's audio section just
// because it came first, and a session with two m=audio sections (e.g. two
// codecs offered as separate lines) would always collapse onto the same one.
type mediaPair struct {
	Offer, Answer *sdp.Media
}

// buildMediaPairs pairs every m= section by index across offer and answer.
// Either side may be nil (SDP never captured) or shorter than the other (a
// capture that missed one message) — a pair simply has a nil Offer or
// Answer in that case, and every comparison below already treats a nil side
// leniently rather than failing outright.
func buildMediaPairs(offer, answer *sdp.SDP) []mediaPair {
	var offerMedia, answerMedia []sdp.Media
	if offer != nil {
		offerMedia = offer.Media
	}
	if answer != nil {
		answerMedia = answer.Media
	}
	n := len(offerMedia)
	if len(answerMedia) > n {
		n = len(answerMedia)
	}
	if n == 0 {
		return nil
	}
	pairs := make([]mediaPair, n)
	for i := 0; i < n; i++ {
		if i < len(offerMedia) {
			pairs[i].Offer = &offerMedia[i]
		}
		if i < len(answerMedia) {
			pairs[i].Answer = &answerMedia[i]
		}
	}
	return pairs
}

// mediaAddr formats a negotiated media section's declared receive address as
// "ip:port", or "" if the section has no connection address or was rejected
// (port 0 — RFC 3264 §6: a zero port means this m-line was declined).
func mediaAddr(m *sdp.Media) string {
	if m == nil || m.ConnAddr == "" || m.Port == 0 {
		return ""
	}
	return fmt.Sprintf("%s:%d", m.ConnAddr, m.Port)
}

// party identifies which side of the negotiation a matched address belongs
// to, independent of which stream field (Src or Dst) it was matched against.
type party int

const (
	partyNone party = iota
	partyOfferer
	partyAnswerer
)

// direction is which way a stream flows, in offer/answer terms — resolved
// from whichever party's declared address the stream's Src or Dst matched.
type direction int

const (
	dirUnknown direction = iota
	dirOffererToAnswerer
	dirAnswererToOfferer
)

// matchAddress finds which media pair (by index) and which party (offerer's
// or answerer's declared address) addr corresponds to. Exact "ip:port" match
// is tried first, across every pair; IP-only match is the fallback, and only
// accepted when it identifies exactly ONE (pair, party) — with several media
// sections typically sharing the same session-level c= address (a single
// party's audio and video both come from the same NIC), IP alone usually
// cannot disambiguate between pairs, and this correctly refuses to guess
// rather than picking one arbitrarily.
func matchAddress(addr string, pairs []mediaPair) (idx int, p party, ok bool) {
	if addr == "" {
		return 0, partyNone, false
	}
	if idx, p, n := scanAddress(pairs, func(a string) bool { return a == addr }); n == 1 {
		return idx, p, true
	} else if n > 1 {
		return 0, partyNone, false
	}

	ip := ipOf(addr)
	if ip == "" {
		return 0, partyNone, false
	}
	if idx, p, n := scanAddress(pairs, func(a string) bool { return ipOf(a) == ip }); n == 1 {
		return idx, p, true
	}
	return 0, partyNone, false
}

// scanAddress counts how many (pair, party) combinations satisfy match,
// returning the last one found and the total count — callers act only when
// the count is exactly 1.
func scanAddress(pairs []mediaPair, match func(string) bool) (idx int, p party, n int) {
	for i, pr := range pairs {
		if a := mediaAddr(pr.Offer); a != "" && match(a) {
			idx, p, n = i, partyOfferer, n+1
		}
		if a := mediaAddr(pr.Answer); a != "" && match(a) {
			idx, p, n = i, partyAnswerer, n+1
		}
	}
	return idx, p, n
}

// classifyStreamPair decides which media pair and which direction a stream
// belongs to. DESTINATION is the primary evidence, checked first: SDP's
// offer/answer addresses declare where each party wants to RECEIVE media
// (RFC 3264), so the observed destination is exactly what SDP predicts and
// promises. SOURCE is only a fallback heuristic, tried when the destination
// doesn't identify anything with confidence — SDP makes no promise at all
// about which address a party will actually SEND from, so a source-only
// match (symmetric RTP) is a common convention, not a guarantee, and must
// never override a destination that does match something.
func classifyStreamPair(s StreamInfo, pairs []mediaPair) (idx int, dir direction, ok bool) {
	if idx, p, matched := matchAddress(s.Dst, pairs); matched {
		// Dst matches party p's declared receive address -> traffic is
		// headed TO p, i.e. FROM the other party.
		if p == partyOfferer {
			return idx, dirAnswererToOfferer, true
		}
		return idx, dirOffererToAnswerer, true
	}
	if idx, p, matched := matchAddress(s.Src, pairs); matched {
		// Src matches party p's declared address -> heuristic: p is
		// presumably the sender (symmetric RTP), so traffic heads FROM p.
		if p == partyOfferer {
			return idx, dirOffererToAnswerer, true
		}
		return idx, dirAnswererToOfferer, true
	}
	return 0, dirUnknown, false
}

// compareStreamToSDP classifies one stream, then checks it against ONLY the
// media pair and direction it was classified into — never a section
// belonging to a different m= line (audio vs video, or one of several
// audio sections), and never both offer and answer addresses indiscriminately.
func compareStreamToSDP(s StreamInfo, pairs []mediaPair) []MediaFinding {
	idx, dir, ok := classifyStreamPair(s, pairs)
	if !ok {
		return []MediaFinding{{
			Level: "info",
			Summary: fmt.Sprintf(
				"No se pudo asociar el stream %s→%s a una sección de media SDP con confianza",
				s.Src, s.Dst),
		}}
	}
	pair := pairs[idx]
	offerM, answerM := pair.Offer, pair.Answer

	// The only normative SDP address is the RECEIVING party's — SDP declares
	// where a party wants to RECEIVE media (RFC 3264), never where it will
	// send FROM. So the only address discrepancy worth flagging here is the
	// DESTINATION; a stream's Src is used only to classify direction when
	// Dst alone can't (classifyStreamPair's fallback), and even then it
	// never becomes a finding on its own — asymmetric RTP, a NAT'd source
	// port, or a different local interface are all completely compatible
	// with a correct negotiation. Flagging Src produced a false SDP
	// violation for exactly that legitimate case.
	var receiverAddr string
	switch dir {
	case dirOffererToAnswerer:
		receiverAddr = mediaAddr(answerM)
	case dirAnswererToOfferer:
		receiverAddr = mediaAddr(offerM)
	}

	var findings []MediaFinding
	if receiverAddr != "" && s.Dst != receiverAddr {
		findings = append(findings, MediaFinding{
			Level: "warn",
			Summary: fmt.Sprintf(
				"Destino RTP observado %s distinto al destino de media anunciado en SDP %s — posible NAT/SBC/media relay; requiere interpretación",
				s.Dst, receiverAddr),
		})
	}
	if offerM != nil && answerM != nil && !directionAllowed(dir, offerM, answerM) {
		findings = append(findings, MediaFinding{
			Level:   "warn",
			Summary: "Se observó RTP en un sentido que la negociación SDP no habilitó",
		})
	}
	return append(findings, compareCodec(s, offerM, answerM)...)
}

// mediaCanSend/mediaCanReceive read sdp.Media.Direction (already parsed by
// internal/protocol/sdp — sendrecv/sendonly/recvonly/inactive, RFC 4566
// §6/RFC 3264) from the writing party's own perspective. A nil section or a
// rejected one (port 0) permits neither.
func mediaCanSend(m *sdp.Media) bool {
	if m == nil || m.Port == 0 {
		return false
	}
	return m.Direction == "sendrecv" || m.Direction == "sendonly" || m.Direction == ""
}

func mediaCanReceive(m *sdp.Media) bool {
	if m == nil || m.Port == 0 {
		return false
	}
	return m.Direction == "sendrecv" || m.Direction == "recvonly" || m.Direction == ""
}

// directionAllowed checks a classified direction against BOTH sides'
// declared sendrecv/sendonly/recvonly/inactive attributes — only called once
// both offerM and answerM exist, since a missing side means there's no
// negotiated restriction to check at all (never treat "we don't know" as
// "not allowed").
func directionAllowed(dir direction, offerM, answerM *sdp.Media) bool {
	switch dir {
	case dirOffererToAnswerer:
		return mediaCanSend(offerM) && mediaCanReceive(answerM)
	case dirAnswererToOfferer:
		return mediaCanSend(answerM) && mediaCanReceive(offerM)
	}
	return true
}

// resolveCodecIdentity looks up pt in whichever side's own codec map defines
// it. Offer and answer can legitimately use DIFFERENT payload type numbers
// for the same negotiated codec, so a PT is resolved via whichever section
// actually declares it, not assumed to come from one fixed side.
func resolveCodecIdentity(pt int, offerM, answerM *sdp.Media) (sdp.Codec, bool) {
	if offerM != nil {
		if c, ok := offerM.Codecs[pt]; ok {
			return c, true
		}
	}
	if answerM != nil {
		if c, ok := answerM.Codecs[pt]; ok {
			return c, true
		}
	}
	return sdp.Codec{}, false
}

func codecIdentityEqual(a, b sdp.Codec) bool {
	return strings.EqualFold(a.Name, b.Name) && a.ClockRate == b.ClockRate && a.Channels == b.Channels
}

// codecAcceptedByBothSides checks that identity genuinely made it into the
// negotiated result — present on BOTH sides by codec identity (name/clock
// rate/channels), not merely "some payload type number exists somewhere".
// Two sides can use different PT numbers for the identical codec (see
// resolveCodecIdentity); comparing raw PT alone would miss that they agree,
// or wrongly accept a PT that collides with an unrelated codec on the other
// side. A missing section (nil) can't constrain anything, so it degrades to
// "satisfied" rather than failing every stream just because one SDP message
// was never captured.
func codecAcceptedByBothSides(identity sdp.Codec, offerM, answerM *sdp.Media) bool {
	inOffer, inAnswer := offerM == nil, answerM == nil
	if offerM != nil {
		for _, c := range offerM.Codecs {
			if codecIdentityEqual(c, identity) {
				inOffer = true
				break
			}
		}
	}
	if answerM != nil {
		for _, c := range answerM.Codecs {
			if codecIdentityEqual(c, identity) {
				inAnswer = true
				break
			}
		}
	}
	return inOffer && inAnswer
}

// compareCodec validates payload type and clock rate against the NEGOTIATED
// codec (present on both sides by identity), not against a single SDP
// message's raw payload type list — see resolveCodecIdentity and
// codecAcceptedByBothSides for why a PT existing on only one side isn't
// enough.
func compareCodec(s StreamInfo, offerM, answerM *sdp.Media) []MediaFinding {
	var findings []MediaFinding
	identity, resolved := resolveCodecIdentity(s.PayloadType, offerM, answerM)
	switch {
	case !resolved:
		findings = append(findings, MediaFinding{
			Level: "warn",
			Summary: fmt.Sprintf(
				"Payload type %d observado en RTP no aparece entre los anunciados en SDP para este medio",
				s.PayloadType),
		})
	case !codecAcceptedByBothSides(identity, offerM, answerM):
		findings = append(findings, MediaFinding{
			Level: "warn",
			Summary: fmt.Sprintf(
				"Payload type %d (%s) observado en RTP no quedó aceptado en la negociación SDP final — presente en un lado pero no en el otro",
				s.PayloadType, identity.Name),
		})
	}
	if s.Stats.ClockAssumed {
		findings = append(findings, MediaFinding{
			Level:   "info",
			Summary: "El clock rate de este stream no pudo confirmarse mediante SDP; se asumió 8kHz",
		})
	} else if resolved && identity.ClockRate > 0 && identity.ClockRate != s.ClockRate {
		findings = append(findings, MediaFinding{
			Level: "warn",
			Summary: fmt.Sprintf(
				"Clock rate observado (%d Hz) distinto al anunciado en SDP para este payload type (%d Hz) — diferencia observada",
				s.ClockRate, identity.ClockRate),
		})
	}
	return findings
}
