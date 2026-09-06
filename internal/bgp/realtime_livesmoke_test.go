//go:build livesmoke

// Live smoke test for the v1.2 RIS Live datasource — READ-ONLY, hits the
// real wss://ris-live.ripe.net/v1/ws/ endpoint. Excluded from `go test
// ./...` by the "livesmoke" build tag: run explicitly with
//
//	go test -tags livesmoke -run TestLiveSmoke_RISLive -v ./internal/bgp/... -timeout 30s
//
// No daemon, no permanent loop, no residual temp file — opens, subscribes
// to one concrete prefix, reads for a short bounded window, closes. If no
// event arrives in that window, that is reported honestly as "no events
// observed" — it is NOT treated as a decoder failure (RIS Live traffic for
// any single prefix is inherently sporadic).
package bgp

import (
	"context"
	"testing"
	"time"

	"trazip/internal/session"
)

func TestLiveSmoke_RISLive(t *testing.T) {
	// A consistently well-announced, high-traffic prefix (Cloudflare
	// 1.1.1.0/24) — same resource already used as a real-wire reference
	// throughout BGP_INTELLIGENCE_ROADMAP.md §23.1.
	const resource = "1.1.1.0/24"
	const window = 15 * time.Second

	mgr := session.NewManager()
	client := NewClient()

	ctx, cancel := context.WithTimeout(context.Background(), window+5*time.Second)
	defer cancel()

	rs, err := PrepareRealtimeSession(ctx, mgr, client, resource, nil)
	if err != nil {
		t.Fatalf("PrepareRealtimeSession: %v", err)
	}
	rs.Run()
	defer rs.Stop()

	deadline := time.After(window)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	var sawConnected bool
	for {
		info := rs.Info()
		if info.State == SessionConnected {
			sawConnected = true
		}
		if info.State == SessionFailed {
			t.Fatalf("session failed: %s", info.LastError)
		}
		select {
		case <-deadline:
			goto done
		case <-ticker.C:
		}
	}
done:
	rs.Stop()
	final := rs.Info()

	if !sawConnected {
		t.Fatalf("never reached CONNECTED against the real RIS Live endpoint (last state=%s, err=%q) — this DOES indicate a real connectivity/subscribe problem, unlike an empty event count below", final.State, final.LastError)
	}

	t.Logf("live smoke result: resource=%s resolvedPrefix=%s receivedEvents=%d lastEventAt=%q reconnectCount=%d",
		resource, final.ResolvedPrefix, final.ReceivedEvents, final.LastEventAt, final.ReconnectCount)

	if final.ReceivedEvents == 0 {
		t.Logf("no events observed in the %s window for %s — RIS Live traffic is sporadic; this is NOT reported as a decoder failure, only as an honest absence of samples in this run", window, resource)
		return
	}

	t.Logf("decoder schema validated implicitly: %d event(s) decoded without error from the live wire", final.ReceivedEvents)
}
