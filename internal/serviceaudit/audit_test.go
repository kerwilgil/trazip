package serviceaudit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCompareExposure(t *testing.T) {
	r := CompareExposure([]int{443, 22, 443, 70000}, []int{22, 80})
	if r.Compliant || len(r.Unexpected) != 1 || r.Unexpected[0] != 443 || len(r.Missing) != 1 || r.Missing[0] != 80 {
		t.Fatalf("unexpected: %+v", r)
	}
}

func TestHTTPAuditDoesNotFollowRedirectOutsideScope(t *testing.T) {
	hit := false
	dst := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer dst.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", dst.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer src.Close()
	r := Result{Metadata: map[string]string{}}
	auditHTTP(context.Background(), &r, src.URL)
	if hit {
		t.Fatal("audit followed redirect outside authorized target")
	}
	if !r.Reachable || r.Metadata["location"] == "" {
		t.Fatalf("redirect evidence missing: %+v", r)
	}
}

func TestCompareExposureCompliant(t *testing.T) {
	r := CompareExposure([]int{80, 443}, []int{443, 80})
	if !r.Compliant {
		t.Fatalf("unexpected: %+v", r)
	}
}

func TestAuditWithEarlyErrorReturnsEmptyFindingsArray(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, port := range []int{8080, 8443} {
		r := Audit(ctx, "127.0.0.1", port)
		if r.Findings == nil {
			t.Fatalf("Audit port %d returned nil Findings; Wails would serialize it as null", port)
		}
		if len(r.Findings) != 0 {
			t.Fatalf("Audit port %d with cancelled context returned findings: %+v", port, r.Findings)
		}
		if r.Err == "" {
			t.Fatalf("Audit port %d with cancelled context should report an error", port)
		}
	}
}

// ============================================================
// CompareExposure — JSON contract & nil-slice guards (hotfix)
// ============================================================

// TestCompareExposure_CaseA_EmptyObservedExpectedNonEmpty verifies
// that when observed is empty and expected has ports, all four slices
// are non-nil and JSON serializes as empty arrays, not null.
func TestCompareExposure_CaseA_EmptyObservedExpectedNonEmpty(t *testing.T) {
	r := CompareExposure([]int{}, []int{22})

	// Non-nil slices
	if r.Observed == nil {
		t.Fatal("Observed must be non-nil")
	}
	if r.Expected == nil {
		t.Fatal("Expected must be non-nil")
	}
	if r.Unexpected == nil {
		t.Fatal("Unexpected must be non-nil")
	}
	if r.Missing == nil {
		t.Fatal("Missing must be non-nil")
	}

	// Correct values
	if len(r.Observed) != 0 {
		t.Errorf("Observed = %v, want []", r.Observed)
	}
	if len(r.Expected) != 1 || r.Expected[0] != 22 {
		t.Errorf("Expected = %v, want [22]", r.Expected)
	}
	if len(r.Unexpected) != 0 {
		t.Errorf("Unexpected = %v, want []", r.Unexpected)
	}
	if len(r.Missing) != 1 || r.Missing[0] != 22 {
		t.Errorf("Missing = %v, want [22]", r.Missing)
	}
	if r.Compliant {
		t.Error("Compliant = true, want false")
	}

	// JSON serialization must produce arrays, not null
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	for _, key := range []string{"observed", "expected", "unexpected", "missing"} {
		if string(m[key]) == "null" {
			t.Errorf("JSON key %q is null, want empty array", key)
		}
	}
}

// TestCompareExposure_CaseB_ObservedEqualsExpected verifies
// that when observed matches expected exactly, all slices are non-nil
// and compliant is true.
func TestCompareExposure_CaseB_ObservedEqualsExpected(t *testing.T) {
	r := CompareExposure([]int{22}, []int{22})

	if r.Observed == nil || r.Expected == nil || r.Unexpected == nil || r.Missing == nil {
		t.Fatal("all slices must be non-nil")
	}
	if len(r.Unexpected) != 0 {
		t.Errorf("Unexpected = %v, want []", r.Unexpected)
	}
	if len(r.Missing) != 0 {
		t.Errorf("Missing = %v, want []", r.Missing)
	}
	if !r.Compliant {
		t.Error("Compliant = false, want true")
	}

	// JSON check
	b, _ := json.Marshal(r)
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	for _, key := range []string{"observed", "expected", "unexpected", "missing"} {
		if string(m[key]) == "null" {
			t.Errorf("JSON key %q is null, want array", key)
		}
	}
}

// TestCompareExposure_CaseC_ObservedExtraExpectedEmpty verifies
// that when expected is empty but observed has ports, Missing is
// non-nil empty array.
func TestCompareExposure_CaseC_ObservedExtraExpectedEmpty(t *testing.T) {
	r := CompareExposure([]int{80}, []int{})

	if r.Missing == nil {
		t.Fatal("Missing must be non-nil")
	}
	if len(r.Unexpected) != 1 || r.Unexpected[0] != 80 {
		t.Errorf("Unexpected = %v, want [80]", r.Unexpected)
	}
	if len(r.Missing) != 0 {
		t.Errorf("Missing = %v, want []", r.Missing)
	}
	if r.Compliant {
		t.Error("Compliant = true, want false")
	}

	// JSON check
	b, _ := json.Marshal(r)
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	if string(m["missing"]) == "null" {
		t.Error("JSON missing is null, want []")
	}
	if string(m["unexpected"]) == "null" {
		t.Error("JSON unexpected is null, want array")
	}
}

// TestCompareExposure_CaseD_BothEmpty verifies
// that when both are empty, all slices are non-nil empty arrays
// and compliant is true.
func TestCompareExposure_CaseD_BothEmpty(t *testing.T) {
	r := CompareExposure([]int{}, []int{})

	if r.Observed == nil || r.Expected == nil || r.Unexpected == nil || r.Missing == nil {
		t.Fatal("all slices must be non-nil")
	}
	if !r.Compliant {
		t.Error("Compliant = false, want true")
	}

	// JSON check
	b, _ := json.Marshal(r)
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	for _, key := range []string{"observed", "expected", "unexpected", "missing"} {
		if string(m[key]) == "null" {
			t.Errorf("JSON key %q is null, want []", key)
		}
	}
}
