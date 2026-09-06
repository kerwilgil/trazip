package bgp

import (
	"encoding/json"
	"reflect"
	"testing"

	"trazip/internal/intel/external"
)

func TestComponentStatusValuesAreDistinct(t *testing.T) {
	values := []ComponentStatus{ComponentOK, ComponentNotApplicable, ComponentUnavailable, ComponentDegraded}
	seen := map[ComponentStatus]bool{}
	for _, v := range values {
		if v == "" {
			t.Fatalf("ComponentStatus value is empty: %+v", values)
		}
		if seen[v] {
			t.Fatalf("duplicate ComponentStatus value: %q", v)
		}
		seen[v] = true
	}
	if len(seen) != 4 {
		t.Fatalf("expected 4 distinct ComponentStatus values, got %d", len(seen))
	}
}

func TestComponentEvidenceSerializesStably(t *testing.T) {
	ev := ComponentEvidence{
		Component: "rpki-validation",
		Status:    ComponentDegraded,
		Disclosure: external.Disclosure{
			Source:      "RIPEstat (RIPE NCC)",
			QueriedAt:   "2026-01-01T00:00:00Z",
			DataSent:    "ASN 262248 + prefijo 192.0.2.0/24",
			CachePolicy: "sin caché local — cada consulta es en vivo",
			Confidence:  "media",
			RateLimit:   "API pública sin autenticación",
		},
		FromCache: false,
		Err:       "RIPEstat HTTP 503",
	}

	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded ComponentEvidence
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// reflect.DeepEqual, not !=: SourceEventIDs ([]string, v1.2 Gate 3
	// P1-3 closure) makes ComponentEvidence non-comparable with ==/!=, but
	// both are nil here (unused by v1.1), so DeepEqual still verifies the
	// exact same round-trip property.
	if !reflect.DeepEqual(decoded, ev) {
		t.Fatalf("round-trip mismatch:\n got: %+v\nwant: %+v", decoded, ev)
	}

	// Status must serialize as its literal string value, not a numeric
	// enum — this is what makes it stable across Go/TS/JSON.
	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}
	if asMap["status"] != "degraded" {
		t.Errorf(`status field = %v, want "degraded"`, asMap["status"])
	}
}

func TestComponentEvidenceErrOmittedWhenNotDegraded(t *testing.T) {
	ev := ComponentEvidence{Component: "as-overview", Status: ComponentOK}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, present := asMap["err"]; present {
		t.Errorf("err field should be omitted when empty, got %+v", asMap)
	}
}
