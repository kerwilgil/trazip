package serviceaudit

import (
	"context"
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
