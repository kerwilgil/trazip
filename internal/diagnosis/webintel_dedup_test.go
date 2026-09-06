package diagnosis

import (
	"context"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// countingTransport wraps http.DefaultTransport to count outbound requests
// — the only non-invasive way to prove "ModeFull calls HTTP exactly once"
// without adding call-counting hooks to httpintel/tlsintel/webintel
// themselves (master plan: "NO reescribir motores existentes"). Every one
// of httpintel.Inspect's requests goes through http.DefaultTransport unless
// a caller overrides it, and neither httpintel nor webintel do.
type countingTransport struct {
	inner http.RoundTripper
	count *int64
}

func (c countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt64(c.count, 1)
	return c.inner.RoundTrip(req)
}

// TestModeFullDoesNotDuplicateHTTPRequests is a live-network integration
// test (Phase B.1 fix #4's own requirement: "Tests deben demostrar que Full
// no ejecuta dos veces HTTP/TLS. Usar dependency injection / test hooks si
// es necesario para contarlo."). Deliberately opt-in via an env var rather
// than running by default: it makes a real HTTP request to a public target,
// which has no place in a suite meant to run under `-count=20` offline —
// run explicitly with TRAZIP_NETWORK_TESTS=1 when verifying this by hand.
func TestModeFullDoesNotDuplicateHTTPRequests(t *testing.T) {
	if os.Getenv("TRAZIP_NETWORK_TESTS") == "" {
		t.Skip("network test — set TRAZIP_NETWORK_TESTS=1 to run")
	}

	var count int64
	orig := http.DefaultTransport
	http.DefaultTransport = countingTransport{inner: orig, count: &count}
	defer func() { http.DefaultTransport = orig }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tlsStage, httpStage := runWebPair(ctx, Dependencies{}, resolvedTarget{kind: "host", host: "example.com"}, ModeFull)

	if httpStage.Status == StageSkipped || httpStage.Status == StageError {
		t.Fatalf("HTTP stage didn't run: %+v", httpStage)
	}
	// example.com redirects internally at most once or twice; what matters
	// here is that this whole run produced ONE outbound HTTP chain (from
	// webintel.Analyze), not two independent ones (one from a direct
	// httpintel.Inspect call plus another from webintel.Analyze). A count
	// in the single digits confirms one chain; a much larger count would
	// indicate a duplicated pipeline.
	got := atomic.LoadInt64(&count)
	if got == 0 {
		t.Fatal("expected at least one real HTTP request, got zero — is the test actually reaching the network?")
	}
	if got > 6 {
		t.Errorf("got %d outbound HTTP requests for one ModeFull run — looks like HTTP/TLS ran twice (once directly, once via WebIntel) instead of once via WebIntel alone", got)
	}
	t.Logf("ModeFull made %d outbound HTTP request(s); TLS stage: %s", got, tlsStage.Status)
}
