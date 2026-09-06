package bgp

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

// --- Fixtures ---
// The announcement/withdrawal messages below are the byte-for-byte probe
// captures recorded in BGP_INTELLIGENCE_ROADMAP.md §23.1 A (host=rrc21,
// 2026-08-19 probe). AS_SET fixtures are synthetic — the probe never
// observed one, but the wire manual documents nested-array path elements
// and the decoder must handle them defensively (§23.1 A).

const fixtureAnnouncement = `{"type":"ris_message","data":{"timestamp":1787141896.080,"peer":"37.49.237.143","peer_asn":"50628","id":"37.49.237.143-01a019f537900000","host":"rrc21.ripe.net","type":"UPDATE","path":[50628,35280,6453,4637,16509],"community":[[6453,86],[6453,3000]],"origin":"IGP","announcements":[{"next_hop":"37.49.237.143","prefixes":["173.82.228.0/24"]}],"withdrawals":[]}}`

const fixtureWithdrawal = `{"type":"ris_message","data":{"timestamp":1787141896.080,"peer":"2001:7f8:54::1:143","peer_asn":"50628","id":"2001:7f8:54::1:143-01a019f537900001","host":"rrc21.ripe.net","type":"UPDATE","path":[],"community":[],"announcements":[],"withdrawals":["2a01:6e00:0:0:0:0:0:0/48"]}}`

func TestDecodeRISMessage_KeepaliveIsValidZeroEvents(t *testing.T) {
	// KEEPALIVE is a valid protocol frame — zero events, zero error.
	evs, err := DecodeRISMessage("1.1.1.0/24", []byte(`{"type":"KEEPALIVE"}`))
	if err != nil {
		t.Errorf("KEEPALIVE unexpected error: %v", err)
	}
	if len(evs) != 0 {
		t.Errorf("KEEPALIVE = %d events, want 0", len(evs))
	}
}

// --- RIS_ERROR (v1.2 P1-3 closure) ---
//
// ris_error is a REAL RIPE protocol frame — distinct from malformed JSON
// or an invalid ris_message.data — and must never be ignored silently: it
// surfaces as an explicit *RISFrameError so the session core can treat it
// as an observable, session-terminal error (see realtime_test.go for the
// session-level assertion that LastError/FAILED actually happen).
func TestDecodeRISMessage_RISError_ObservableNotSilent(t *testing.T) {
	evs, err := DecodeRISMessage("1.1.1.0/24", []byte(`{"type":"ris_error","data":{"message":"invalid filter"}}`))
	if err == nil {
		t.Fatal("expected a non-nil error for ris_error, got nil")
	}
	var risErr *RISFrameError
	if !errors.As(err, &risErr) {
		t.Fatalf("expected *RISFrameError, got %T: %v", err, err)
	}
	if risErr.Message != "invalid filter" {
		t.Errorf("RISFrameError.Message = %q, want %q", risErr.Message, "invalid filter")
	}
	if len(evs) != 0 {
		t.Errorf("got %d events for ris_error, want 0", len(evs))
	}
}

func TestDecodeRISMessage_NonUpdateSubtype(t *testing.T) {
	raw := `{"type":"ris_message","data":{"id":"x","type":"OPEN"}}`
	evs, err := DecodeRISMessage("1.1.1.0/24", []byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evs) != 0 {
		t.Errorf("got %d events for non-UPDATE subtype, want 0", len(evs))
	}
}

func TestDecodeRISMessage_MalformedJSON_NoPanicNoFabrication(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("DecodeRISMessage panicked on malformed input: %v", r)
		}
	}()
	evs, err := DecodeRISMessage("1.1.1.0/24", []byte(`{not json`))
	if err == nil {
		t.Fatal("expected an error for malformed JSON, got nil")
	}
	if len(evs) != 0 {
		t.Errorf("got %d fabricated events on decode error, want 0", len(evs))
	}
}

func TestDecodeRISMessage_MalformedDataField(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("DecodeRISMessage panicked: %v", r)
		}
	}()
	raw := `{"type":"ris_message","data":"not an object"}`
	evs, err := DecodeRISMessage("1.1.1.0/24", []byte(raw))
	if err == nil {
		t.Fatal("expected an error for malformed data field, got nil")
	}
	if len(evs) != 0 {
		t.Errorf("got %d fabricated events, want 0", len(evs))
	}
}

func TestDecodeRISMessage_Announcement(t *testing.T) {
	evs, err := DecodeRISMessage("173.82.228.0/24", []byte(fixtureAnnouncement))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Type != EventAnnouncement {
		t.Errorf("Type = %q, want announcement", ev.Type)
	}
	if ev.Source != "ris-live" {
		t.Errorf("Source = %q, want ris-live", ev.Source)
	}
	if ev.SourceMessageID != "37.49.237.143-01a019f537900000" {
		t.Errorf("SourceMessageID = %q", ev.SourceMessageID)
	}
	if ev.Prefix != "173.82.228.0/24" {
		t.Errorf("Prefix = %q", ev.Prefix)
	}
	if ev.Peer != "37.49.237.143" {
		t.Errorf("Peer = %q", ev.Peer)
	}
	// peer_asn arrives as a wire string "50628" — must parse to int 50628,
	// never left as 0 / never assumed already-int (§23.1).
	if ev.PeerASN != 50628 {
		t.Errorf("PeerASN = %d, want 50628 (parsed from wire string)", ev.PeerASN)
	}
	if len(ev.Path) != 5 {
		t.Fatalf("Path length = %d, want 5", len(ev.Path))
	}
	if !ev.Origin.Determinate || ev.Origin.ASN != 16509 {
		t.Errorf("Origin = %+v, want Determinate=true ASN=16509 (last path element)", ev.Origin)
	}
	wantID := "37.49.237.143-01a019f537900000:announcement:173.82.228.0/24:0"
	if ev.ID != wantID {
		t.Errorf("ID = %q, want %q", ev.ID, wantID)
	}
}

func TestDecodeRISMessage_Withdrawal(t *testing.T) {
	evs, err := DecodeRISMessage("2a01:6e00::/48", []byte(fixtureWithdrawal))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Type != EventWithdrawal {
		t.Errorf("Type = %q, want withdrawal", ev.Type)
	}
	if ev.Prefix != "2a01:6e00:0:0:0:0:0:0/48" {
		t.Errorf("Prefix = %q", ev.Prefix)
	}
	// Un withdrawal no trae path en el wire — nunca fabricado.
	if len(ev.Path) != 0 {
		t.Errorf("Path = %+v, want empty (never fabricated for a withdrawal)", ev.Path)
	}
	if ev.Origin.Determinate {
		t.Errorf("Origin.Determinate = true for a withdrawal, want false (never fabricated)")
	}
}

func TestDecodeRISMessage_NPrefixesProduceNEvents(t *testing.T) {
	raw := `{"type":"ris_message","data":{"timestamp":1700000000.5,"peer":"1.2.3.4","peer_asn":"100","id":"msg-3prefixes","type":"UPDATE","path":[100,200,300],"announcements":[{"next_hop":"1.2.3.4","prefixes":["10.0.0.0/24","10.0.1.0/24","10.0.2.0/24"]}],"withdrawals":[]}}`
	evs, err := DecodeRISMessage("10.0.0.0/8", []byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evs) != 3 {
		t.Fatalf("got %d events, want 3 (one per announced prefix)", len(evs))
	}
	ids := map[string]bool{}
	for _, ev := range evs {
		if ids[ev.ID] {
			t.Errorf("duplicate event ID %q — event IDs must be unique per fan-out", ev.ID)
		}
		ids[ev.ID] = true
		if ev.SourceMessageID != "msg-3prefixes" {
			t.Errorf("SourceMessageID = %q, want shared %q", ev.SourceMessageID, "msg-3prefixes")
		}
	}
	if len(ids) != 3 {
		t.Errorf("got %d unique IDs, want 3", len(ids))
	}
}

func TestDecodeBGPPath_Flat(t *testing.T) {
	raw := `{"type":"ris_message","data":{"id":"m1","type":"UPDATE","peer_asn":"1","path":[1,2,3],"announcements":[{"prefixes":["9.9.9.0/24"]}]}}`
	evs, err := DecodeRISMessage("9.9.9.0/24", []byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	path := evs[0].Path
	if len(path) != 3 {
		t.Fatalf("path length = %d, want 3", len(path))
	}
	for i, want := range []int{1, 2, 3} {
		if path[i].Kind != PathElementASN || path[i].ASN != want {
			t.Errorf("path[%d] = %+v, want ASN %d", i, path[i], want)
		}
	}
	if !evs[0].Origin.Determinate || evs[0].Origin.ASN != 3 {
		t.Errorf("Origin = %+v, want Determinate=true ASN=3", evs[0].Origin)
	}
}

func TestDecodeBGPPath_ASSetIntermediate(t *testing.T) {
	raw := `{"type":"ris_message","data":{"id":"m2","type":"UPDATE","peer_asn":"1","path":[100,[65001,65002],200],"announcements":[{"prefixes":["9.9.9.0/24"]}]}}`
	evs, err := DecodeRISMessage("9.9.9.0/24", []byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	path := evs[0].Path
	if len(path) != 3 {
		t.Fatalf("path length = %d, want 3 (AS_SET preserved as one element, never flattened)", len(path))
	}
	if path[1].Kind != PathElementASSet {
		t.Fatalf("path[1].Kind = %q, want as_set", path[1].Kind)
	}
	if len(path[1].Set) != 2 || path[1].Set[0] != 65001 || path[1].Set[1] != 65002 {
		t.Errorf("path[1].Set = %v, want [65001 65002] in received order", path[1].Set)
	}
	// AS_SET is intermediate, not final — origin is still the last (ASN)
	// element, fully determinate.
	if !evs[0].Origin.Determinate || evs[0].Origin.ASN != 200 {
		t.Errorf("Origin = %+v, want Determinate=true ASN=200 (intermediate AS_SET does not affect origin)", evs[0].Origin)
	}
}

func TestDecodeBGPPath_ASSetFinal_OriginIndeterminate(t *testing.T) {
	raw := `{"type":"ris_message","data":{"id":"m3","type":"UPDATE","peer_asn":"1","path":[100,200,[65001,65002]],"announcements":[{"prefixes":["9.9.9.0/24"]}]}}`
	evs, err := DecodeRISMessage("9.9.9.0/24", []byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	path := evs[0].Path
	if len(path) != 3 || path[2].Kind != PathElementASSet {
		t.Fatalf("path = %+v, want AS_SET preserved as final element", path)
	}
	origin := evs[0].Origin
	if origin.Determinate {
		t.Errorf("Origin.Determinate = true for an AS_SET-final path, want false (v1.2 P1-1)")
	}
	if origin.ASN != 0 {
		t.Errorf("Origin.ASN = %d for indeterminate origin, want 0 (never a fabricated ASN)", origin.ASN)
	}
	if origin.Reason == "" {
		t.Error("Origin.Reason must be explicit when Determinate=false")
	}
	if !strings.Contains(origin.Reason, "65001") || !strings.Contains(origin.Reason, "65002") {
		t.Errorf("Origin.Reason = %q, want it to cite the AS_SET members as evidence", origin.Reason)
	}
}

func TestDecodeBGPPath_Empty(t *testing.T) {
	raw := `{"type":"ris_message","data":{"id":"m4","type":"UPDATE","peer_asn":"1","path":[],"announcements":[{"prefixes":["9.9.9.0/24"]}]}}`
	evs, err := DecodeRISMessage("9.9.9.0/24", []byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evs[0].Path) != 0 {
		t.Errorf("Path = %+v, want empty", evs[0].Path)
	}
	origin := evs[0].Origin
	if origin.Determinate || origin.ASN != 0 || origin.Reason != "empty path" {
		t.Errorf("Origin = %+v, want {Determinate:false ASN:0 Reason:\"empty path\"}", origin)
	}
}

func TestDecodeBGPPath_MalformedElementDiscarded(t *testing.T) {
	// "garbage" is neither an int nor a []int — must be discarded, never
	// cause a panic, never get fabricated into an ASN.
	raw := `{"type":"ris_message","data":{"id":"m5","type":"UPDATE","peer_asn":"1","path":[100,"garbage",300],"announcements":[{"prefixes":["9.9.9.0/24"]}]}}`
	evs, err := DecodeRISMessage("9.9.9.0/24", []byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	path := evs[0].Path
	if len(path) != 2 {
		t.Fatalf("path length = %d, want 2 (malformed element discarded)", len(path))
	}
	if path[0].ASN != 100 || path[1].ASN != 300 {
		t.Errorf("path = %+v, want [ASN 100, ASN 300]", path)
	}
	if !evs[0].Origin.Determinate || evs[0].Origin.ASN != 300 {
		t.Errorf("Origin = %+v, want Determinate=true ASN=300", evs[0].Origin)
	}
}

func TestParsePeerASN(t *testing.T) {
	// v1.2 P1-3 closure, caso B: peer_asn inválido debe reportar ok=false
	// explícito — nunca colapsar silenciosamente a 0 como si fuera un ASN
	// real (0 también es inválido por sí mismo: reservado, RFC 7607).
	cases := []struct {
		in     string
		wantN  int
		wantOK bool
	}{
		{"50628", 50628, true},
		{" 100 ", 100, true},
		{"", 0, false},
		{"not-a-number", 0, false},
		{"0", 0, false},
		{"-5", 0, false},
	}
	for _, c := range cases {
		gotN, gotOK := parsePeerASN(c.in)
		if gotN != c.wantN || gotOK != c.wantOK {
			t.Errorf("parsePeerASN(%q) = (%d, %v), want (%d, %v)", c.in, gotN, gotOK, c.wantN, c.wantOK)
		}
	}
}

func TestRISTimestampToRFC3339_PreservesFraction(t *testing.T) {
	got := risTimestampToRFC3339(1787141896.080)
	parsed, err := time.Parse(time.RFC3339Nano, got)
	if err != nil {
		t.Fatalf("output %q not parseable as RFC3339Nano: %v", got, err)
	}
	if parsed.Unix() != 1787141896 {
		t.Errorf("Unix() = %d, want 1787141896", parsed.Unix())
	}
	wantNsec := int64(80_000_000)
	if diff := int64(math.Abs(float64(parsed.Nanosecond() - int(wantNsec)))); diff > 1_000_000 {
		t.Errorf("Nanosecond() = %d, want ~%d (fraction must survive the float->time conversion, never truncated to zero)", parsed.Nanosecond(), wantNsec)
	}
}

// v1.2 P1-3 closure, caso C: ausente/inválido/no finito nunca fabrica el
// epoch 1970 — string vacía, honestamente "desconocido".
func TestRISTimestampToRFC3339_InvalidNeverFabricates1970(t *testing.T) {
	cases := []float64{0, -1, math.NaN(), math.Inf(1), math.Inf(-1)}
	for _, ts := range cases {
		if got := risTimestampToRFC3339(ts); got != "" {
			t.Errorf("risTimestampToRFC3339(%v) = %q, want empty string (never fabricated as epoch 1970)", ts, got)
		}
	}
}

func TestNormalizeBGPOrigin_CaseInsensitive(t *testing.T) {
	// Confirmed wire discrepancy (§23.1 A): the manual documents lowercase
	// ("igp"), the real wire sends uppercase ("IGP") — decoder must never
	// assume either case.
	cases := map[string]string{
		"IGP":        "igp",
		"igp":        "igp",
		"Incomplete": "incomplete",
		" EGP ":      "egp",
	}
	for in, want := range cases {
		if got := normalizeBGPOrigin(in); got != want {
			t.Errorf("normalizeBGPOrigin(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- origin_changed / path_changed exactness (v1.2 P1-1 closure) ---

func TestOriginChanged_DeterminateToDeterminate_Different(t *testing.T) {
	prev := OriginResolution{Determinate: true, ASN: 100}
	curr := OriginResolution{Determinate: true, ASN: 200}
	if !OriginChanged(prev, curr) {
		t.Error("determinate AS100 -> determinate AS200 must trigger origin_changed")
	}
}

func TestOriginChanged_DeterminateToIndeterminate(t *testing.T) {
	prev := OriginResolution{Determinate: true, ASN: 100}
	curr := OriginResolution{Determinate: false, ASN: 0, Reason: "as_set final: [1 2], origen no determinable"}
	if OriginChanged(prev, curr) {
		t.Error("determinate AS100 -> AS_SET indeterminate must NOT trigger origin_changed")
	}
}

func TestOriginChanged_IndeterminateToDeterminate(t *testing.T) {
	prev := OriginResolution{Determinate: false, ASN: 0, Reason: "as_set final: [1 2], origen no determinable"}
	curr := OriginResolution{Determinate: true, ASN: 100}
	if OriginChanged(prev, curr) {
		t.Error("AS_SET indeterminate -> determinate AS100 must NOT trigger origin_changed")
	}
}

func TestOriginChanged_IndeterminateToIndeterminate_DifferentComposition(t *testing.T) {
	prev := OriginResolution{Determinate: false, ASN: 0, Reason: "as_set final: [1 2], origen no determinable"}
	curr := OriginResolution{Determinate: false, ASN: 0, Reason: "as_set final: [3 4], origen no determinable"}
	if OriginChanged(prev, curr) {
		t.Error("AS_SET A -> AS_SET B (different composition) must NOT trigger origin_changed")
	}
}

func TestOriginChanged_DeterminateToDeterminate_SameASN(t *testing.T) {
	prev := OriginResolution{Determinate: true, ASN: 100}
	curr := OriginResolution{Determinate: true, ASN: 100}
	if OriginChanged(prev, curr) {
		t.Error("same determinate ASN must NOT trigger origin_changed")
	}
}

func TestPathChanged_ASSetToASSet_DifferentComposition(t *testing.T) {
	prev := BGPPath{{Kind: PathElementASN, ASN: 100}, {Kind: PathElementASSet, Set: []int{1, 2}}}
	curr := BGPPath{{Kind: PathElementASN, ASN: 100}, {Kind: PathElementASSet, Set: []int{3, 4}}}
	if !PathChanged(prev, curr) {
		t.Error("AS_SET composition change must trigger path_changed even though origin_changed does not")
	}
	if OriginChanged(deriveOrigin(prev, false), deriveOrigin(curr, false)) {
		t.Error("origin_changed must stay false for this same case (both indeterminate)")
	}
}

func TestPathChanged_Identical(t *testing.T) {
	a := BGPPath{{Kind: PathElementASN, ASN: 100}, {Kind: PathElementASN, ASN: 200}}
	b := BGPPath{{Kind: PathElementASN, ASN: 100}, {Kind: PathElementASN, ASN: 200}}
	if PathChanged(a, b) {
		t.Error("identical paths must not report path_changed")
	}
}

// --- Gate 2 runtime closure: semantic wire validation (v1.2 P1-3) ---

// Case A: a malformed FINAL path element must never let the previous
// (real) element look like the true last-element/origin.
func TestDecodeBGPPath_MalformedFinalElement_OriginIndeterminate(t *testing.T) {
	raw := `{"type":"ris_message","data":{"id":"m6","type":"UPDATE","peer_asn":"1","timestamp":1700000000,"path":[100,200,"corrupt"],"announcements":[{"prefixes":["9.9.9.0/24"]}]}}`
	evs, err := DecodeRISMessage("9.9.9.0/24", []byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	path := evs[0].Path
	if len(path) != 2 || path[0].ASN != 100 || path[1].ASN != 200 {
		t.Fatalf("path = %+v, want [ASN 100, ASN 200] (corrupt final element discarded)", path)
	}
	origin := evs[0].Origin
	if origin.Determinate {
		t.Errorf("Origin.Determinate = true, want false — must NOT infer origin=200 from a path truncated by a corrupt final element")
	}
	if origin.ASN != 0 {
		t.Errorf("Origin.ASN = %d, want 0 (never fabricated from a truncated path)", origin.ASN)
	}
	if origin.Reason == "" {
		t.Error("Origin.Reason must be explicit when the final path element is malformed")
	}
}

// Regression guard: the P1-3 "malformed final element" fix must not touch
// a VALID AS_SET as the final element — that keeps the P1-1 indeterminate
// semantics untouched.
func TestDecodeBGPPath_ValidASSetFinal_StillWorksAfterP1_3(t *testing.T) {
	raw := `{"type":"ris_message","data":{"id":"m7","type":"UPDATE","peer_asn":"1","timestamp":1700000000,"path":[100,[65001,65002]],"announcements":[{"prefixes":["9.9.9.0/24"]}]}}`
	evs, err := DecodeRISMessage("9.9.9.0/24", []byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	origin := evs[0].Origin
	if origin.Determinate {
		t.Errorf("Origin.Determinate = true for a valid final AS_SET, want false")
	}
	if len(evs[0].Path) != 2 || evs[0].Path[1].Kind != PathElementASSet {
		t.Errorf("Path = %+v, want AS_SET preserved as final element", evs[0].Path)
	}
}

// Case B: invalid peer_asn must never produce a real event with a
// fabricated PeerASN=0.
func TestDecodeRISMessage_InvalidPeerASN_NoFabricatedEvent(t *testing.T) {
	cases := []string{
		`{"type":"ris_message","data":{"id":"m8","type":"UPDATE","peer_asn":"","timestamp":1700000000,"announcements":[{"prefixes":["9.9.9.0/24"]}]}}`,
		`{"type":"ris_message","data":{"id":"m9","type":"UPDATE","peer_asn":"not-a-number","timestamp":1700000000,"announcements":[{"prefixes":["9.9.9.0/24"]}]}}`,
		`{"type":"ris_message","data":{"id":"m10","type":"UPDATE","peer_asn":"0","timestamp":1700000000,"announcements":[{"prefixes":["9.9.9.0/24"]}]}}`,
	}
	for _, raw := range cases {
		evs, err := DecodeRISMessage("9.9.9.0/24", []byte(raw))
		if err == nil {
			t.Errorf("DecodeRISMessage(%q): expected error for invalid peer_asn, got nil", raw)
		}
		if len(evs) != 0 {
			t.Errorf("DecodeRISMessage(%q): got %d events, want 0 — never a real event with a fabricated PeerASN", raw, len(evs))
		}
	}
}

// Case C (message-level, complementary to TestRISTimestampToRFC3339_InvalidNeverFabricates1970):
// a missing timestamp field must not reject the whole message — the event
// is still emitted, just with an honest empty Timestamp.
func TestDecodeRISMessage_MissingTimestamp_EmptyNotFabricated1970(t *testing.T) {
	raw := `{"type":"ris_message","data":{"id":"m11","type":"UPDATE","peer_asn":"1","announcements":[{"prefixes":["9.9.9.0/24"]}]}}`
	evs, err := DecodeRISMessage("9.9.9.0/24", []byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1 (a missing timestamp does not reject the message, per P1-3 policy)", len(evs))
	}
	if evs[0].Timestamp != "" {
		t.Errorf("Timestamp = %q, want empty (never fabricated 1970)", evs[0].Timestamp)
	}
}

// Case D: an empty SourceMessageID must never seed a plausible-looking
// Event ID.
func TestDecodeRISMessage_EmptySourceMessageID_NoFabricatedIDs(t *testing.T) {
	raw := `{"type":"ris_message","data":{"id":"","type":"UPDATE","peer_asn":"1","timestamp":1700000000,"announcements":[{"prefixes":["9.9.9.0/24"]}]}}`
	evs, err := DecodeRISMessage("9.9.9.0/24", []byte(raw))
	if err == nil {
		t.Fatal("expected error for empty SourceMessageID, got nil")
	}
	if len(evs) != 0 {
		t.Errorf("got %d events with an empty source id, want 0 — never a plausible-looking ID from an inexistent source id", len(evs))
	}
}

// Case E: an empty/invalid prefix skips only that item — it never rejects
// the whole message, and it never fabricates an announcement/withdrawal.
func TestDecodeRISMessage_InvalidPrefix_SkipsOnlyThatItem(t *testing.T) {
	raw := `{"type":"ris_message","data":{"id":"m12","type":"UPDATE","peer_asn":"1","timestamp":1700000000,"path":[100],"announcements":[{"prefixes":["9.9.9.0/24","","not-a-prefix","10.0.0.0/8"]}],"withdrawals":["","11.0.0.0/8"]}}`
	evs, err := DecodeRISMessage("9.9.9.0/24", []byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evs) != 3 {
		t.Fatalf("got %d events, want 3 (invalid prefixes skipped, valid ones kept)", len(evs))
	}
	got := map[string]bool{}
	for _, ev := range evs {
		got[ev.Prefix] = true
	}
	for _, want := range []string{"9.9.9.0/24", "10.0.0.0/8", "11.0.0.0/8"} {
		if !got[want] {
			t.Errorf("missing expected event for prefix %q", want)
		}
	}
}
