package httpintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInspectFollowsRedirectChain(t *testing.T) {
	var final *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/middle", http.StatusFound)
	})
	mux.HandleFunc("/middle", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/end", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/end", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Final", "yes")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	final = srv

	res := Inspect(context.Background(), final.URL+"/start", "", 0, 0, false)
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if len(res.Redirects) != 3 {
		t.Fatalf("Redirects = %d hops, want 3 (start, middle, end)", len(res.Redirects))
	}
	if res.FinalStatus != http.StatusOK {
		t.Errorf("FinalStatus = %d, want 200", res.FinalStatus)
	}
	if !strings.HasSuffix(res.FinalURL, "/end") {
		t.Errorf("FinalURL = %q, want it to end in /end", res.FinalURL)
	}
	if res.Headers.Get("X-Final") != "yes" {
		t.Errorf("final headers missing X-Final")
	}
	if res.Redirects[0].StatusCode != http.StatusFound || res.Redirects[1].StatusCode != http.StatusMovedPermanently {
		t.Errorf("hop statuses = %+v, want [302 301 200]", []int{res.Redirects[0].StatusCode, res.Redirects[1].StatusCode, res.Redirects[2].StatusCode})
	}
}

func TestInspectRespectsMaxRedirects(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := Inspect(context.Background(), srv.URL+"/loop", "", 3, 0, false)
	if res.Err == "" {
		t.Fatal("expected an error when the redirect limit is exceeded")
	}
	if len(res.Redirects) != 4 { // 3 redirects allowed + 1 more that trips the limit
		t.Errorf("Redirects = %d, want 4 (maxRedirects=3 means 4 attempts)", len(res.Redirects))
	}
}

func TestInspectSecurityHeaders(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := Inspect(context.Background(), srv.URL+"/", "", 0, 0, false)
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	present := map[string]bool{}
	for _, h := range res.SecurityHeaders {
		present[h.Name] = h.Present
	}
	if !present["Strict-Transport-Security"] {
		t.Error("HSTS should be reported present")
	}
	if !present["X-Content-Type-Options"] {
		t.Error("X-Content-Type-Options should be reported present")
	}
	if present["Content-Security-Policy"] {
		t.Error("CSP was not set by the server and should be reported absent")
	}
}

func TestInspectDetectsCDNSignals(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Ray", "abc123-EWR")
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := Inspect(context.Background(), srv.URL+"/", "", 0, 0, false)
	if len(res.Signals) == 0 {
		t.Fatal("expected at least one CDN signal from Server+cf-ray headers")
	}
	foundEvidence := false
	for _, s := range res.Signals {
		if s.Label == "Cloudflare" && s.Evidence != "" {
			foundEvidence = true
		}
	}
	if !foundEvidence {
		t.Errorf("expected a Cloudflare signal with evidence, got %+v", res.Signals)
	}
}

func TestInspectBodyTruncation(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("A", 1000)))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := Inspect(context.Background(), srv.URL+"/", "", 0, 100, true)
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if !res.BodyTruncated {
		t.Error("expected BodyTruncated=true when body exceeds maxBodyBytes")
	}
	if len(res.Body) != 100 {
		t.Errorf("Body length = %d, want 100 (the cap)", len(res.Body))
	}
}

func TestInspectBodyNotKeptByDefault(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret-ish body"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := Inspect(context.Background(), srv.URL+"/", "", 0, 0, false)
	if res.Body != nil {
		t.Error("Body should be nil when keepBody=false, per the no-body-retention-by-default rule")
	}
	if res.BodyBytesRead == 0 {
		t.Error("BodyBytesRead should still be reported even when the body itself is discarded")
	}
}

func TestInspectHEADMethod(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("server saw method %s, want HEAD", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := Inspect(context.Background(), srv.URL+"/", http.MethodHead, 0, 0, false)
	if res.FinalStatus != http.StatusNoContent {
		t.Errorf("FinalStatus = %d, want 204", res.FinalStatus)
	}
}

func TestInspectConnectionRefused(t *testing.T) {
	res := Inspect(context.Background(), "http://127.0.0.1:1", "", 0, 0, false)
	if res.Err == "" {
		t.Error("expected a connection error for an unreachable host")
	}
}

func TestInspectInvalidURL(t *testing.T) {
	res := Inspect(context.Background(), "://not-a-url", "", 0, 0, false)
	if res.Err == "" {
		t.Error("expected an error for a malformed URL")
	}
}
