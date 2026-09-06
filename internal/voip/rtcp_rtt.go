package voip

import (
	"sort"
	"time"

	"trazip/internal/protocol/rtcp"
)

// rtcpObservation pairs a parsed RTCP packet with when TRAZIP's own capture
// point saw it. RTT (RFC 3550 §6.4.1) needs that arrival time, and it is not a
// property of the packet's protocol fields alone — it belongs to the
// stateful correlator, not the stateless internal/protocol/rtcp parser, so it
// lives here rather than growing rtcp.Packet.
type rtcpObservation struct {
	Packet  rtcp.Packet
	Arrival time.Time
}

// ntpUnixEpochDeltaSec is the gap between the NTP epoch (1900-01-01) and the
// Unix epoch (1970-01-01), including the leap days in between — the standard
// constant for converting between the two.
const ntpUnixEpochDeltaSec = 2208988800

// ntpShortFromTime converts a wall-clock time into NTP's "short" 32-bit
// format: the middle 32 bits of a 64-bit NTP timestamp (low 16 bits of the
// seconds field, high 16 bits of the fractional field) — the same format LSR
// and DLSR are already expressed in, so all three can be combined by plain
// subtraction.
func ntpShortFromTime(t time.Time) uint32 {
	sec := uint32(t.Unix()+ntpUnixEpochDeltaSec) & 0xFFFF
	// (ns << 32) / 1e9 done in uint64 to avoid the overflow a naive
	// nanosecond*scale multiplication hits near the top of the ns range.
	frac32 := uint32((uint64(t.Nanosecond()) << 32) / 1_000_000_000)
	return sec<<16 | frac32>>16
}

// ntpShort extracts the same middle-32-bits format directly from a Sender
// Report's NTP seconds/fraction fields (RFC 3550 §6.4.1), for comparison
// against a report block's LSR.
func ntpShort(seconds, fraction uint32) uint32 {
	return (seconds&0xFFFF)<<16 | fraction>>16
}

// maxSaneRTTNTP bounds a computed RTT to 60 seconds (in NTP-short units:
// 1/65536 s each) — anything beyond that means the SR/RR pairing or the
// capture's own clock is unreliable, not that the call really has a minute of
// round-trip delay. Well under half of 2^32, so it can never itself be
// mistaken for a wrapped value by the rollover handling below.
const maxSaneRTTNTP = 60 * 65536

// ntpShortSub computes a-b on NTP-short values (uint32, RFC 3550 §4's "short
// format": 16 bits of seconds + 16 bits of fraction) as a signed duration,
// correctly across a rollover of the 16-bit seconds field (~18.2 hours).
//
// Plain int64(a)-int64(b) — this function's predecessor — is only correct
// when a and b sit on the same side of a rollover. A SR sent right before the
// 16-bit seconds field wraps and a RR arriving a few seconds after produces a
// LARGE NEGATIVE plain difference even though the true elapsed time is small
// and positive: e.g. a=0x0000_1000 (just after wrap) and b=0xFFFF_F000 (just
// before) is a real ~0.03s gap, but int64(a)-int64(b) is roughly -2^32.
//
// uint32 subtraction wraps automatically to the correct value in that case
// (Go's unsigned overflow is defined, two's-complement, modular arithmetic —
// not UB), so casting the uint32 DIFFERENCE (not the operands) to a signed
// type recovers the true short-duration result as long as the real elapsed
// time is itself less than 2^31 short-units (~9.1 hours) — always true here,
// since maxSaneRTTNTP rejects anything past 60 real seconds long before this
// distinction would matter.
func ntpShortSub(a, b uint32) int64 {
	return int64(int32(a - b))
}

// estimateRTT implements RFC 3550 §6.4.1's RTT formula — RTT = A - LSR - DLSR —
// for one stream's SSRC, from the RTCP observations captured on both legs of
// its 5-tuple (both directions, already merged and time-ordered by the
// caller... actually sorted here, since callers pass them unsorted).
//
// It deliberately mirrors what a REAL endpoint does, not a third-party replay
// of every SR ever seen: a report block's LSR names whichever Sender Report
// THAT RECEIVER last actually received — not necessarily the most recent SR
// this capture happened to see go by. An intervening SR (SR2, observed after
// SR1 but before the report block) may not have reached the receiver yet, may
// have been lost, or may simply have arrived after the receiver already built
// its report — RFC 3550 §6.4.1 makes no promise that a receiver's LSR
// references the LATEST SR sent, only some SR it actually got. So every SR
// observed for this SSRC before a given report (not just the newest one) is
// a valid match — accept a report block's LSR whenever it matches ANY of
// them, chosen deterministically by scanning in arrival order.
//
// The result is an ESTIMATE, not a measurement, and the name says so on
// purpose. RFC 3550's A is the moment the RR arrives at the ORIGINAL SR's
// SENDER — a fact only that endpoint can know directly. A passive third-party
// capture has no way to observe that; it can only substitute the timestamp of
// when TRAZIP's OWN capture point saw the RR go by. Those two moments coincide
// exactly only if the capture point sits exactly where the SR's sender does.
// In every other placement — capturing on a span port, at a gateway, anywhere
// but right at one of the two call endpoints — propagation delay between the
// capture point and the real endpoint gets folded into the result as error,
// and that error grows with the capture's distance from the endpoint. This
// function has no way to know or bound that distance, so it cannot report a
// margin of error — only that the number is an estimate. Callers (Diagnose,
// the UI) must treat it accordingly: lower confidence, ProvInferred rather
// than ProvObserved, and a visible "estimado" label rather than a bare "ms".
//
// Returns (nil, reason) whenever the SR/RR correlation can't be established
// with confidence. It never returns a computed 0ms as a stand-in for "no
// data" — the zero value of *float64 is nil, and a real 0ms result is
// returned as a non-nil pointer to 0.
func estimateRTT(obs []rtcpObservation, ssrc uint32) (rttMs *float64, reason string) {
	sorted := append([]rtcpObservation(nil), obs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Arrival.Before(sorted[j].Arrival) })

	// For every SR NTP-short value seen for this SSRC so far, the most
	// recent prior observation's arrival — overwritten as the scan advances
	// in arrival order, so a report block only ever matches an SR that was
	// genuinely observed BEFORE it, never one that arrives later, and (if
	// the same 16-bit-truncated value were ever seen twice — the seconds
	// field wraps every ~18.2h) always resolves to the LATEST such prior
	// occurrence, not whichever happened to be seen first.
	//
	// In practice this can never change the computed RTT: RFC 3550's LSR is
	// the 32-bit truncated NTP value ITSELF, carried directly in the report
	// block and used as a plain scalar in the A-LSR-DLSR subtraction — not a
	// reference to a specific SR packet. Two different SR packets that
	// happen to truncate to the same LSR value are, for this arithmetic,
	// indistinguishable; tracking the timestamp (rather than a bare bool)
	// costs nothing and keeps the map honest about what it represents, but
	// simulating a real ~18.2h collision to prove a numeric difference isn't
	// attempted here — there isn't one to prove.
	seenSR := make(map[uint32]time.Time)
	sawAnyReportForSSRC := false

	for _, o := range sorted {
		p := o.Packet
		if p.Type == rtcp.TypeSR && p.SSRC == ssrc {
			seenSR[ntpShort(p.NTPSeconds, p.NTPFraction)] = o.Arrival
		}
		for _, blk := range p.Reports {
			if blk.SSRC != ssrc || blk.LSR == 0 {
				// LSR == 0 is RFC 3550 §6.4.1's own sentinel for "this
				// receiver hasn't gotten an SR yet" — the one genuine
				// "unavailable" case, not an invented one.
				continue
			}
			sawAnyReportForSSRC = true
			if _, ok := seenSR[blk.LSR]; !ok {
				reason = "el LSR del informe no coincide con ninguna SR de este stream observada antes de este informe"
				continue
			}
			a := ntpShortFromTime(o.Arrival)
			// A - LSR - DLSR, each subtraction done with rollover-safe
			// arithmetic (ntpShortSub) rather than plain int64 casts — see
			// its doc comment for the rollover this specifically fixes.
			// DLSR is used exactly as reported, including 0 — RFC 3550
			// defines no sentinel value for DLSR the way it does for LSR;
			// a DLSR of 0 (near-instant report generation) or any other
			// value is either physically plausible or gets caught by the
			// sanity bounds below, never rejected on sight.
			rtt := ntpShortSub(a, blk.LSR) - int64(blk.DLSR)
			if rtt <= 0 || rtt > maxSaneRTTNTP {
				reason = "el cálculo de RTT dio un resultado fuera de rango"
				continue
			}
			ms := float64(rtt) / 65536.0 * 1000.0
			return &ms, ""
		}
	}
	if !sawAnyReportForSSRC {
		return nil, "no se observó un informe RTCP con LSR para este stream"
	}
	if reason == "" {
		reason = "no se observó un par SR/RR válido para este stream"
	}
	return nil, reason
}

// ssrcRelevant reports whether p carries any information about ssrc — either
// p is itself a Sender Report FROM that SSRC (an SR's own SSRC field names
// its sender's outgoing stream, RFC 3550 §6.4.1), or at least one of its
// Report Blocks names ssrc as the SSRC being reported ON. RFC 3550 keeps
// these two fields conceptually distinct on purpose — "whose packet this is"
// and "which SSRC a Report Block talks about" — and conflating them is
// exactly how one stream's numbers end up filed under another's SSRC.
func ssrcRelevant(p rtcp.Packet, ssrc uint32) bool {
	if p.Type == rtcp.TypeSR && p.SSRC == ssrc {
		return true
	}
	for _, blk := range p.Reports {
		if blk.SSRC == ssrc {
			return true
		}
	}
	return false
}

// filterObservationsForSSRC narrows a set of RTCP observations down to only
// what genuinely describes ssrc.
//
// The observations arrive gathered per IP pair (correlate.go's rtcpReports
// map), not per stream: a capture can carry several RTP streams — and their
// RTCP — between the exact same two addresses on different ports, so IP pair
// alone cannot tell them apart. This is the level where they finally do:
// every consumer downstream (the filtered RTCPReports exposed to the frontend,
// buildRTCPSummary, estimateRTT) sees only what belongs to this SSRC after
// this runs, not "everything seen for this IP pair, hope the caller filters."
//
// Two Report Blocks in the SAME compound packet can legitimately name two
// DIFFERENT SSRCs — an endpoint juggling several streams reports on all of
// them in one datagram — so filtering happens per Report Block, not per
// packet. And critically: the Sender Report fields (SSRC/PacketCount/
// OctetCount/NTP*/RTPTimestamp) are kept ONLY when the packet's own SR is
// genuinely from ssrc's sender. A foreign SR sharing a datagram with a Report
// Block about ssrc must never lend its packet/octet/timestamp counts to
// ssrc's summary — those describe a different stream's outgoing traffic
// entirely, and doing so would silently attribute one stream's counters to
// another's SSRC.
func filterObservationsForSSRC(obs []rtcpObservation, ssrc uint32) []rtcpObservation {
	out := make([]rtcpObservation, 0, len(obs))
	for _, o := range obs {
		p := o.Packet
		if !ssrcRelevant(p, ssrc) {
			continue
		}
		filtered := rtcp.Packet{Type: rtcp.TypeRR, SSRC: ssrc}
		if p.Type == rtcp.TypeSR && p.SSRC == ssrc {
			filtered.Type = rtcp.TypeSR
			filtered.SSRC = p.SSRC
			filtered.NTPSeconds, filtered.NTPFraction = p.NTPSeconds, p.NTPFraction
			filtered.RTPTimestamp = p.RTPTimestamp
			filtered.PacketCount, filtered.OctetCount = p.PacketCount, p.OctetCount
		}
		// A real SR from ssrc's own sender never carries a report block about
		// itself (its blocks describe what IT received from others), so this
		// only ever adds entries in the "foreign SR carrying our block" case —
		// which is exactly the case this function exists to isolate cleanly.
		for _, blk := range p.Reports {
			if blk.SSRC == ssrc {
				filtered.Reports = append(filtered.Reports, blk)
			}
		}
		out = append(out, rtcpObservation{Packet: filtered, Arrival: o.Arrival})
	}
	return out
}

// buildRTCPSummary summarizes what RTCP reported about one stream's SSRC,
// keeping the Receiver's account (Report Blocks naming this SSRC) and the
// Sender's own account (this SSRC's own Sender Report) as two independently
// nil fields — see RTCPSummary's doc comment for why they must never be
// merged into one "remote" bag.
//
// Each half is tracked ONLY from the observations that actually populate it:
// a Sender Report existing for this SSRC never causes Receiver to be
// constructed, and a Report Block naming this SSRC never causes Sender to be
// constructed. An earlier version of this function created a single flat
// struct as soon as EITHER kind of observation appeared, which meant a
// stream whose sender emits SRs but whose actual receiver was never captured
// (or never sent RTCP back) showed FractionLostPct/JitterTicks/CumulativeLost
// all at their Go zero value — indistinguishable from "the receiver reported
// 0% loss and 0 jitter", when in truth nothing was ever reported. Splitting
// the two halves makes that state impossible to represent: Receiver is
// simply nil, and every caller (Diagnose, the UI) must already handle nil.
//
// The two can arrive in different compound packets over the stream's life —
// this returns the freshest observation of each, independently.
func buildRTCPSummary(obs []rtcpObservation, ssrc uint32, clockRate int, clockAssumed bool) *RTCPSummary {
	sorted := append([]rtcpObservation(nil), obs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Arrival.Before(sorted[j].Arrival) })

	var out *RTCPSummary
	for _, o := range sorted {
		p := o.Packet
		if p.Type == rtcp.TypeSR && p.SSRC == ssrc {
			if out == nil {
				out = &RTCPSummary{}
			}
			out.Sender = &RTCPSenderSummary{
				PacketCount:  p.PacketCount,
				OctetCount:   p.OctetCount,
				NTPSeconds:   p.NTPSeconds,
				NTPFraction:  p.NTPFraction,
				RTPTimestamp: p.RTPTimestamp,
			}
		}
		for _, blk := range p.Reports {
			if blk.SSRC != ssrc {
				continue
			}
			if out == nil {
				out = &RTCPSummary{}
			}
			out.Receiver = &RTCPReceiverSummary{
				FractionLostPct: blk.FractionLost,
				CumulativeLost:  blk.CumulativeLost,
				HighestSeq:      blk.HighestSeq,
				JitterTicks:     blk.JitterTicks,
				LSR:             blk.LSR,
				DLSR:            blk.DLSR,
			}
		}
	}
	if out == nil {
		return nil
	}
	// Converting an assumed 8kHz clock to milliseconds would silently launder
	// a guess into a number that looks measured — see JitterMs's doc comment.
	if out.Receiver != nil && !clockAssumed && clockRate > 0 {
		ms := float64(out.Receiver.JitterTicks) / float64(clockRate) * 1000
		out.Receiver.JitterMs = &ms
	}
	out.EstimatedRTTMs, out.EstimatedRTTUnavailableReason = estimateRTT(obs, ssrc)
	return out
}
